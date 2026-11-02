//! Literal predecessor validator and additive combined-fault controls.
use super::*;
use std::collections::BTreeSet;

fn old_new(
    request: &WholeFunctionRequest<'_>,
    scan: &ScanResult,
    actions: &[ControlledAction],
) -> Result<Verified, Refusal> {
    let bytes = request.code;
    if request.base_address == 0 || !(5..=80).contains(&bytes.len()) {
        return Err(Refusal::NoPatchWindow);
    }
    let range = AddressRange::new(request.base_address, bytes.len())?;
    if request.entries.identity != request.identity {
        return Err(Refusal::StaleGeneration);
    }
    if request.entries.scope != range {
        return Err(Refusal::InvalidRange);
    }
    if request.entries.completeness != EntryCompleteness::Complete
        || request.entries.resumes != ResumeObligation::NoneExist
        || request.entries.entries.iter().any(|e| e.requires_endbr)
    {
        return Err(Refusal::UnresolvedEntry);
    }
    let policy = request.allocation;
    if policy.max_candidates > 256 || policy.max_mappings > 1 || policy.max_mapped_bytes > 8192 {
        return Err(Refusal::AllocationUnavailable);
    }
    let items = scan.instructions();
    if scan.snapshot() != bytes
        || items.first().map(|i| i.address()) != Some(range.start())
        || items.last().map(|i| i.instruction().next_ip()) != Some(range.end())
    {
        return Err(Refusal::InvalidRange);
    }
    let mut successors = vec![Vec::new(); items.len()];
    let mut leaders = BTreeSet::from([0]);
    for (n, item) in items.iter().enumerate() {
        let i = item.instruction();
        let raw = &bytes[item.offset()..item.offset() + item.len()];
        if i.has_lock_prefix()
            || i.has_rep_prefix()
            || i.has_repne_prefix()
            || i.segment_prefix() != Register::None
            || i.is_privileged()
        {
            return Err(unsupported());
        }
        qualify_instruction(i)?;
        match i.flow_control() {
            FlowControl::Next => {
                if !scalar(i) || n + 1 == items.len() {
                    return Err(unsupported());
                }
                successors[n].push(n + 1);
            }
            FlowControl::Return if raw == [0xc3] => {}
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                if !matches!(
                    raw,
                    [0x70..=0x7f, _]
                        | [0x0f, 0x80..=0x8f, _, _, _, _]
                        | [0xeb, _]
                        | [0xe9, _, _, _, _]
                ) || i.op_count() != 1
                    || i.op_kind(0) != OpKind::NearBranch64
                {
                    return Err(unsupported());
                }
                let target = i.near_branch_target();
                let destination = items
                    .iter()
                    .position(|x| x.address() == target)
                    .ok_or_else(unsupported)?;
                if destination == 0 || destination == n {
                    return Err(unsupported());
                }
                successors[n].push(destination);
                leaders.insert(destination);
                if i.flow_control() == FlowControl::ConditionalBranch {
                    if n + 1 == items.len() {
                        return Err(unsupported());
                    }
                    successors[n].push(n + 1);
                    leaders.insert(n + 1);
                }
            }
            _ => return Err(unsupported()),
        }
    }
    let mut reached = vec![false; items.len()];
    let mut pending = vec![0];
    while let Some(n) = pending.pop() {
        if !reached[n] {
            reached[n] = true;
            pending.extend(successors[n].iter().copied());
        }
    }
    if items
        .iter()
        .enumerate()
        .any(|(n, i)| !reached[n] && i.instruction().mnemonic() != Mnemonic::Nop)
    {
        return Err(unsupported());
    }
    let returns: Vec<_> = items
        .iter()
        .enumerate()
        .filter(|(n, i)| reached[*n] && i.instruction().flow_control() == FlowControl::Return)
        .map(|(_, i)| i.address())
        .collect();
    if !(1..=4).contains(&returns.len()) {
        return Err(unsupported());
    }
    let mut can_return: Vec<_> = items
        .iter()
        .map(|i| returns.contains(&i.address()))
        .collect();
    for _ in 0..items.len() {
        for (n, next) in successors.iter().enumerate() {
            let reaches = next.iter().any(|&to| can_return[to]);
            can_return[n] |= reaches;
        }
    }
    if reached
        .iter()
        .zip(&can_return)
        .any(|(&r, &exit)| r && !exit)
    {
        return Err(unsupported());
    }
    let mut blocks = 0;
    let mut n = 0;
    while n < items.len() {
        if !reached[n] {
            n += 1;
            continue;
        }
        blocks += 1;
        loop {
            let terminal = items[n].instruction().flow_control() != FlowControl::Next
                || n + 1 == items.len()
                || !reached[n + 1]
                || leaders.contains(&(n + 1));
            n += 1;
            if terminal {
                break;
            }
        }
    }
    if blocks > 32 {
        return Err(unsupported());
    }
    let expected: Vec<_> = leaders
        .into_iter()
        .filter(|&n| reached[n])
        .map(|n| items[n].address())
        .collect();
    if request
        .entries
        .entries
        .iter()
        .map(|e| e.address)
        .collect::<Vec<_>>()
        != expected
    {
        return Err(Refusal::UnresolvedEntry);
    }
    let roles: Vec<_> = std::iter::once(range.start()).chain(returns).collect();
    if actions.iter().map(|a| a.logical_pc).collect::<Vec<_>>() != roles
        || actions
            .iter()
            .enumerate()
            .any(|(n, a)| actions[..n].iter().any(|b| b.control == a.control))
    {
        return Err(Refusal::InvalidPlan);
    }
    Ok(Verified { end: range.end() })
}

fn parity(
    request: &WholeFunctionRequest<'_>,
    scan: &ScanResult,
    actions: &[ControlledAction],
) -> Result<u64, Refusal> {
    let actual = Verified::new(request, scan, actions).map(|proof| proof.end);
    assert_eq!(
        actual,
        old_new(request, scan, actions).map(|proof| proof.end)
    );
    actual
}

#[test]
fn shared_whole_graph_preserves_profile_and_combined_fault_precedence() {
    for (bytes, leaders, returns, accepted) in [
        (
            &[0x90, 0x90, 0x74, 0, 0xc3][..],
            &[0, 4][..],
            &[4][..],
            true,
        ),
        (
            &[0x90, 0xeb, 1, 0x90, 0xc3][..],
            &[0, 4][..],
            &[4][..],
            true,
        ),
        (
            &[0x90, 0x75, 0xfd, 0x90, 0xc3][..],
            &[0, 3][..],
            &[4][..],
            false,
        ),
        (
            &[0x90, 0x75, 0xfe, 0x90, 0xc3][..],
            &[0, 1, 3][..],
            &[4][..],
            false,
        ),
        (
            &[0x90, 0xeb, 2, 0x31, 0xc0, 0xc3][..],
            &[0, 5][..],
            &[5][..],
            false,
        ),
        (
            &[0xe8, 0xfb, 0x0f, 0, 0, 0xc3][..],
            &[0][..],
            &[5][..],
            false,
        ),
        (
            &[0x90, 0x90, 0xe2, 0, 0xc3][..],
            &[0, 4][..],
            &[4][..],
            false,
        ),
        (
            &[0x90, 0x90, 0xe3, 0, 0xc3][..],
            &[0, 4][..],
            &[4][..],
            false,
        ),
    ] {
        let f = Fixture::new(bytes, leaders, returns);
        assert_eq!(
            parity(&f.request(), &f.scan(), &f.actions).is_ok(),
            accepted,
            "{bytes:02x?}"
        );
    }
    let qualifier =
        Refusal::UnsupportedSemantics("Cpuid has no qualified A1 relocation contract".into());
    for (bytes, expected) in [
        (&[0x0f, 0xa2, 0xeb, 0x7f, 0xc3][..], qualifier.clone()),
        (&[0xeb, 0x7f, 0x0f, 0xa2, 0xc3][..], unsupported()),
        (&[0xf3, 0x0f, 0xa2, 0xeb, 0x7f, 0xc3][..], unsupported()),
        (&[0xeb, 2, 0x0f, 0xa2, 0xc3][..], qualifier),
    ] {
        let f = Fixture::new(bytes, &[0], &[(bytes.len() - 1) as u64]);
        assert_eq!(parity(&f.request(), &f.scan(), &f.actions), Err(expected));
    }
    let mut f = Fixture::short();
    f.entries.completeness = EntryCompleteness::Incomplete;
    f.allocation.max_candidates = 257;
    let scan = f.scan();
    let mut request = f.request();
    request.base_address = 0;
    request.identity.generation += 1;
    assert_eq!(
        parity(&request, &scan, &f.actions),
        Err(Refusal::NoPatchWindow)
    );
    request.base_address = PC;
    assert_eq!(
        parity(&request, &scan, &f.actions),
        Err(Refusal::StaleGeneration)
    );
    request.identity = f.entries.identity;
    assert_eq!(
        parity(&request, &scan, &f.actions),
        Err(Refusal::UnresolvedEntry)
    );
    f.entries.scope = range(PC, SHORT.len() - 1);
    assert_eq!(
        parity(&f.request(), &scan, &f.actions),
        Err(Refusal::InvalidRange)
    );
    f.entries.scope = range(PC, SHORT.len());
    f.entries.completeness = EntryCompleteness::Complete;
    let wrong = InstructionScanner::default()
        .scan(&[0x90, 0x90, 0x90, 0x90, 0xc3], PC)
        .unwrap();
    assert_eq!(
        parity(&f.request(), &wrong, &f.actions),
        Err(Refusal::AllocationUnavailable)
    );
    f.allocation.max_candidates = 256;
    assert_eq!(
        parity(&f.request(), &wrong, &f.actions),
        Err(Refusal::InvalidRange)
    );
    f.entries.entries.pop();
    f.actions.pop();
    assert_eq!(
        parity(&f.request(), &scan, &f.actions),
        Err(Refusal::UnresolvedEntry)
    );
    f.entries = Fixture::short().entries;
    assert_eq!(
        parity(&f.request(), &scan, &f.actions),
        Err(Refusal::InvalidPlan)
    );
}
