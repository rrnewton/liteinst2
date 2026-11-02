use super::*;
use crate::contracts::{
    CodeIdentity, EntryCompleteness, EntryProvenance, LegalEntry, LegalEntrySet, ResumeObligation,
    SourceIdentity,
};
use crate::emission::PlanningRequest;
use crate::planner::HookSemantics;
use crate::quiescent::{
    AllocationPolicy, InstallRequest, PunContext, SearchPolicy, plan_pun_with_context_core,
    qualify_instruction,
};
use crate::scanner::{InstructionScanner, ScanResult};
use crate::search::{RefusalClass, SearchEvidence, SearchScope};

// Predecessor arithmetic is deliberately independent of the shared queries.
fn original_head(
    physical: u64,
    len: usize,
    prefixes: usize,
    source: AddressRange,
    block: AddressRange,
    max_displaced: usize,
) -> Result<(AddressRange, AddressRange), Refusal> {
    let displaced = AddressRange::new(physical, len)?;
    let consumed = AddressRange::new(physical, 5 + prefixes)?;
    if !(1..=4).contains(&len)
        || prefixes >= len
        || len > max_displaced
        || !block.covers(displaced)
        || !source.covers(consumed)
        || physical / 64 != (displaced.end() - 1) / 64
    {
        return Err(Refusal::NoPatchWindow);
    }
    Ok((displaced, consumed))
}

fn original_store(
    physical: u64,
    len: usize,
    source: AddressRange,
) -> Result<AddressRange, Refusal> {
    let store_len = len.next_power_of_two();
    let store_address = physical.min((physical | 63) - (store_len as u64 - 1));
    let store_range = AddressRange::new(store_address, store_len)?;
    if !source.covers(store_range) {
        return Err(Refusal::NoPatchWindow);
    }
    Ok(store_range)
}

fn original_targets(
    physical: u64,
    len: usize,
    prefixes: usize,
    source: AddressRange,
    code: &[u8],
) -> Result<PunTargets, Refusal> {
    let offset = (physical - source.start()) as usize;
    let mut fixed = [0_u8; 4];
    let free = len - prefixes - 1;
    fixed[free..].copy_from_slice(&code[offset + len..offset + 5 + prefixes]);
    let next = i128::from(physical) + 5 + prefixes as i128;
    let low = u64::try_from(next + i128::from(i32::from_le_bytes(fixed)))
        .map_err(|_| Refusal::AllocationUnavailable)?;
    let window = AddressRange::new(low, 1_usize << (8 * free))?;
    Ok(PunTargets {
        window,
        offset,
        free,
        next: u64::try_from(next).unwrap(),
        fixed,
    })
}

#[test]
fn staged_geometry_matches_predecessor_and_refuses_malformed_public_inputs() {
    for base in [0, 0x1000, u64::MAX - 127] {
        for line_offset in 60..64 {
            let physical = base + line_offset;
            for len in 1..=4 {
                for prefixes in 0..=len {
                    for left in [0, 1] {
                        for right in [0, 1, 4, 8] {
                            let source =
                                AddressRange::new(physical - left, left as usize + len + right)
                                    .unwrap();
                            let block = AddressRange::new(physical, len).unwrap();
                            for maximum in [0, len, 80] {
                                let expected =
                                    original_head(physical, len, prefixes, source, block, maximum);
                                let actual =
                                    pun_head(physical, len, prefixes, source, block, maximum);
                                assert_eq!(
                                    actual
                                        .clone()
                                        .map(|head| (head.displaced(), head.consumed())),
                                    expected
                                );
                                let Ok(head) = actual else { continue };
                                assert_eq!(
                                    head.store_range(),
                                    original_store(physical, len, source)
                                );
                                for fill in [0, 0x7f, 0x80, 0xff] {
                                    let code = vec![fill; source.len() as usize];
                                    let expected =
                                        original_targets(physical, len, prefixes, source, &code);
                                    let actual = head.targets(&code);
                                    assert_eq!(actual, expected);
                                    if let Ok(targets) = actual {
                                        let constraints = targets.constraints();
                                        assert_eq!(constraints.next, targets.next());
                                        assert_eq!(constraints.entries, [false; 4]);
                                        assert_eq!(
                                            constraints.fixed,
                                            std::array::from_fn(|n| {
                                                (n >= targets.free_bytes())
                                                    .then_some(targets.raw_displacement()[n])
                                            })
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let source = AddressRange::new(0x1000, 16).unwrap();
    assert_eq!(
        pun_head(0x1000, 0, usize::MAX, source, source, 80),
        Err(Refusal::InvalidRange)
    );
    assert_eq!(
        pun_head(0x1000, 1, usize::MAX, source, source, 80),
        Err(Refusal::InvalidRange)
    );
    assert_eq!(
        pun_head(0x1000, 5, 0, source, source, 80),
        Err(Refusal::NoPatchWindow)
    );
    assert_eq!(
        pun_head(u64::MAX - 1, 1, 0, source, source, 80),
        Err(Refusal::InvalidRange)
    );
    let later = AddressRange::new(0x1001, 15).unwrap();
    assert_eq!(
        pun_head(0x1000, 1, 0, source, later, 80),
        Err(Refusal::NoPatchWindow)
    );
    assert_eq!(
        pun_head(0x1000, 1, 0, later, source, 80),
        Err(Refusal::NoPatchWindow)
    );
    let head = pun_head(0x1000, 3, 0, source, source, 80).unwrap();
    assert_eq!(head.targets(&[0; 4]), Err(Refusal::InvalidRange));
    assert_eq!(
        head.targets(&[0; 5]).unwrap().window(),
        AddressRange::new(0x1005, 65536).unwrap()
    );
    assert_eq!(
        head.targets(&[0, 0, 0, 1, 0]).unwrap().window(),
        AddressRange::new(0x11005, 65536).unwrap()
    );
}

#[test]
fn rel32_constraints_preserve_ordered_alphabet_and_all_mask_conflicts() {
    let original = [
        0x06, 0x07, 0x0e, 0x16, 0x17, 0x1e, 0x1f, 0x27, 0x2f, 0x37, 0x3f, 0x60, 0x61, 0xce,
    ];
    assert_eq!(ENTRY_BYTES, original);
    for mask in 0..16 {
        for fixed in [
            [None; 4],
            [Some(0); 4],
            [Some(0xff); 4],
            [Some(0x06), Some(0x07), Some(0xd4), Some(0xd5)],
            [None, Some(0x66), Some(0x90), Some(0x4c)],
        ] {
            let entries = std::array::from_fn(|n| mask & (1 << n) != 0);
            let constraints = Rel32Constraints {
                next: 0x1000,
                fixed,
                entries,
            };
            for digit in 0..4 {
                for byte in 0..=255 {
                    let expected = fixed[digit].is_none_or(|value| value == byte)
                        && (!entries[digit] || original.contains(&byte));
                    assert_eq!(constraints.allows(digit, byte), Some(expected));
                }
            }
            assert_eq!(constraints.allows(4, 0x06), None);
            assert_eq!(constraints.allows(usize::MAX, 0x06), None);
        }
    }
}

// Literal predecessor prefix through target-window construction.
fn original_prefix(
    request: &PlanningRequest<'_>,
    scan: &ScanResult,
    source: AddressRange,
    prefixes: usize,
    search_evidence: &mut SearchEvidence,
    context: PunContext,
) -> Result<PunTargets, Refusal> {
    let parent_scope = context.scope;
    let physical = request.logical_pc;
    let scope = SearchScope {
        physical_pc: Some(physical),
        prefix_count: Some(prefixes),
        ..parent_scope
    };
    let instruction = scan
        .instructions()
        .iter()
        .find(|item| item.address() == physical)
        .ok_or(Refusal::NotInstructionHead)?;
    let len = instruction.len();
    let displaced = AddressRange::new(physical, len)?;
    let consumed = AddressRange::new(physical, 5 + prefixes)?;
    if !(1..=4).contains(&len)
        || prefixes >= len
        || len > request.search.max_displaced_bytes
        || !request.block.covers(displaced)
        || !source.covers(consumed)
        || physical / 64 != (displaced.end() - 1) / 64
    {
        search_evidence.qualification(scope, &Refusal::NoPatchWindow);
        return Err(Refusal::NoPatchWindow);
    }
    if context.callback_free || request.semantics != HookSemantics::ReplaceFirst {
        qualify_instruction(instruction.instruction())
            .inspect_err(|reason| search_evidence.qualification(scope, reason))?;
    }
    if request
        .entries
        .entries
        .iter()
        .any(|entry| displaced.contains(entry.address) && entry.requires_endbr)
    {
        return Err(Refusal::UnsupportedSemantics(
            "CET IBT landing pad in pun".into(),
        ));
    }
    // A direct branch into the middle of the original instruction is positive
    // evidence against the caller's non-overlapping stream claim.
    if scan.instructions().iter().any(|item| {
        matches!(
            item.instruction().op0_kind(),
            iced_x86::OpKind::NearBranch16
                | iced_x86::OpKind::NearBranch32
                | iced_x86::OpKind::NearBranch64
        ) && displaced.contains(item.instruction().near_branch_target())
            && item.instruction().near_branch_target() != physical
    }) {
        return Err(Refusal::NotInstructionHead);
    }
    let store_len = len.next_power_of_two();
    // x86 has no three-byte MOV. Keep a four-byte store in this cache line by
    // preserving the successor byte, or the preceding byte at offset 61.
    let store_address = physical.min((physical | 63) - (store_len as u64 - 1));
    let store_range = AddressRange::new(store_address, store_len)?;
    if !source.covers(store_range) {
        search_evidence.qualification(scope, &Refusal::NoPatchWindow);
        return Err(Refusal::NoPatchWindow);
    }
    // Preserve prior hooks even for ReplaceFirst. Consumed successor and store
    // padding bytes deliberately remain current-view inputs, not this guard.
    request
        .require_original(displaced)
        .inspect_err(|reason| search_evidence.qualification(scope, reason))?;
    let offset = (physical - source.start()) as usize;
    let mut fixed = [0_u8; 4];
    let free = len - prefixes - 1;
    fixed[free..].copy_from_slice(&request.code[offset + len..offset + 5 + prefixes]);
    let next = i128::from(physical) + 5 + prefixes as i128;
    let low = u64::try_from(next + i128::from(i32::from_le_bytes(fixed)))
        .map_err(|_| Refusal::AllocationUnavailable)?;
    let window = AddressRange::new(low, 1_usize << (8 * free))?;
    Ok(PunTargets {
        window,
        offset,
        free,
        next: u64::try_from(next).unwrap(),
        fixed,
    })
}

unsafe extern "C" fn noop(_: *mut crate::trampoline::HookContext) {}

fn compare_core_refusal(
    base: u64,
    original: &[u8],
    current: &[u8],
    cet: bool,
    expected: Refusal,
    expected_class: Option<RefusalClass>,
) {
    let source = AddressRange::new(base, original.len()).unwrap();
    let scan = InstructionScanner::default().scan(original, base).unwrap();
    let identity = CodeIdentity {
        source: SourceIdentity([42; 32]),
        mapping: 1,
        generation: 1,
    };
    let entries = LegalEntrySet {
        identity,
        scope: source,
        provenance: EntryProvenance::Declared("pure feasibility precedence fixture".into()),
        completeness: EntryCompleteness::AllInstructionHeads,
        entries: if cet {
            vec![LegalEntry {
                address: base,
                requires_endbr: true,
            }]
        } else {
            vec![]
        },
        resumes: ResumeObligation::NoneExist,
    };
    // Stop after the geometry prefix without invoking an emitter. A successful
    // prefix must reach this original resource guard, with its original record.
    let allocation = AllocationPolicy {
        ranges: vec![],
        preferred_address: None,
        max_candidates: 1,
        max_mappings: 0,
        max_mapped_bytes: 0,
    };
    let request = InstallRequest {
        identity,
        code: original,
        base_address: base,
        function: source,
        block: source,
        logical_pc: base,
        entries: &entries,
        hook: noop,
        semantics: HookSemantics::Observe,
        allocation: &allocation,
        search: SearchPolicy::default(),
    };
    let original_request = PlanningRequest::live(&request);
    let request = original_request.with_code(current);
    let context = PunContext {
        scope: SearchScope::default(),
        callback_free: false,
        exact_target: None,
    };
    let mut old_evidence = SearchEvidence::default();
    let old_reason = match original_prefix(&request, &scan, source, 0, &mut old_evidence, context) {
        Err(reason) => reason,
        Ok(_) => {
            old_evidence.refusal(
                SearchScope {
                    physical_pc: Some(base),
                    prefix_count: Some(0),
                    ..context.scope
                },
                RefusalClass::ResourceCapacity,
                &Refusal::AllocationUnavailable,
            );
            Refusal::AllocationUnavailable
        }
    };
    let mut actual_evidence = SearchEvidence::default();
    let actual = plan_pun_with_context_core(
        &request,
        &scan,
        source,
        &[],
        0,
        &mut actual_evidence,
        context,
    )
    .unwrap_err();
    assert_eq!(actual, expected);
    assert_eq!(actual, old_reason);
    assert_eq!(actual_evidence, old_evidence);
    assert_eq!(
        actual_evidence
            .refusals
            .iter()
            .map(|item| item.class)
            .collect::<Vec<_>>(),
        expected_class.into_iter().collect::<Vec<_>>()
    );
    assert!(actual_evidence.runs.is_empty());
    assert!(!actual_evidence.accepted && !actual_evidence.classification_complete);
}

#[test]
fn actual_core_keeps_first_refusal_and_exact_qualification_evidence() {
    let locked = [0xf0, 0x01, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90];
    compare_core_refusal(
        0x103d,
        &locked,
        &locked,
        false,
        Refusal::UnsupportedSemantics("Add has no qualified A1 relocation contract".into()),
        Some(RefusalClass::UnsupportedSemantics),
    );
    let nop = [0x0f, 0x1f, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90];
    compare_core_refusal(
        0x103d,
        &nop,
        &nop,
        true,
        Refusal::UnsupportedSemantics("CET IBT landing pad in pun".into()),
        None,
    );
    let interior = [0x0f, 0x1f, 0x00, 0xeb, 0xfc, 0x90, 0x90, 0x90];
    compare_core_refusal(
        0x103d,
        &interior,
        &interior,
        false,
        Refusal::NotInstructionHead,
        None,
    );
    compare_core_refusal(
        0x103d,
        &nop,
        &nop,
        false,
        Refusal::NoPatchWindow,
        Some(RefusalClass::Prerequisite),
    );
    let original = [0x90; 8];
    let mut current = [0xcc, 0, 0, 0, 0x80, 0x90, 0x90, 0x90];
    compare_core_refusal(
        0x1040,
        &original,
        &current,
        false,
        Refusal::ExpectedBytesChanged,
        Some(RefusalClass::Unclassified),
    );
    compare_core_refusal(
        0x1040,
        &original,
        &current[..7],
        false,
        Refusal::InvalidRange,
        Some(RefusalClass::Unclassified),
    );
    current[0] = 0x90;
    compare_core_refusal(
        0x1040,
        &original,
        &current,
        false,
        Refusal::AllocationUnavailable,
        None,
    );
    let mut current = nop;
    current[3..5].fill(0);
    compare_core_refusal(
        u64::MAX - 67,
        &nop,
        &current,
        false,
        Refusal::InvalidRange,
        None,
    );
    compare_core_refusal(
        0x1040,
        &original,
        &[0x90, 0, 0, 0, 0, 0x90, 0x90, 0x90],
        false,
        Refusal::AllocationUnavailable,
        Some(RefusalClass::ResourceCapacity),
    );
}
