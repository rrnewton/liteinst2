//! Literal predecessor reference and additive shared-CFG parity controls.
use super::*;
use std::collections::BTreeSet;

fn old_admit(bytes: &[u8], base: u64) -> Result<IntegerLeafCertificate, SetupRefusal> {
    let refusal = SetupRefusal::EntryExit;
    if bytes.is_empty() || bytes.len() > 256 || base == 0 {
        return Err(refusal);
    }
    let end = base.checked_add(bytes.len() as u64).ok_or(refusal)?;
    let scan = InstructionScanner::default()
        .scan(bytes, base)
        .map_err(|_| refusal)?;
    let items = scan.instructions();
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
            return Err(refusal);
        }
        match i.flow_control() {
            FlowControl::Next => {
                if !ordinary(i) || n + 1 == items.len() {
                    return Err(refusal);
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
                    return Err(refusal);
                }
                let target = i.near_branch_target();
                let destination = items
                    .iter()
                    .position(|x| x.address() == target)
                    .ok_or(refusal)?;
                if target == item.address() {
                    return Err(refusal);
                }
                successors[n].push(destination);
                leaders.insert(destination);
                if i.flow_control() == FlowControl::ConditionalBranch {
                    if n + 1 == items.len() {
                        return Err(refusal);
                    }
                    successors[n].push(n + 1);
                    leaders.insert(n + 1);
                }
            }
            _ => return Err(refusal),
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
    // Compilers can leave alignment NOPs between reachable blocks. No other
    // unreachable instruction/data is silently classified as code or skipped.
    if items
        .iter()
        .enumerate()
        .any(|(n, x)| !reached[n] && x.instruction().mnemonic() != Mnemonic::Nop)
    {
        return Err(refusal);
    }
    let returns: Vec<_> = items
        .iter()
        .enumerate()
        .filter(|(n, x)| reached[*n] && x.instruction().flow_control() == FlowControl::Return)
        .map(|(_, x)| x.address())
        .collect();
    if !(1..=4).contains(&returns.len()) {
        return Err(refusal);
    }
    // Every reachable node must have a CFG path to an ordinary RET. This is
    // structural exit coverage, not a proof that input-dependent loops terminate.
    let mut can_return: Vec<_> = items
        .iter()
        .map(|x| returns.contains(&x.address()))
        .collect();
    for _ in 0..items.len() {
        for (n, next) in successors.iter().enumerate() {
            let reaches = next.iter().any(|&target| can_return[target]);
            can_return[n] |= reaches;
        }
    }
    if reached
        .iter()
        .zip(&can_return)
        .any(|(&r, &exit)| r && !exit)
    {
        return Err(refusal);
    }
    let mut blocks = Vec::new();
    let mut n = 0;
    while n < items.len() {
        if !reached[n] {
            n += 1;
            continue;
        }
        let first = n;
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
        blocks.push((items[first].address(), items[n - 1].instruction().next_ip()));
    }
    if blocks.len() > 32 {
        return Err(refusal);
    }
    let mut edges = Vec::new();
    for (n, next) in successors.iter().enumerate() {
        if reached[n] {
            edges.extend(
                next.iter()
                    .map(|&to| (items[n].address(), items[to].address())),
            );
        }
    }
    Ok(IntegerLeafCertificate {
        entry: base,
        end,
        heads: items.iter().map(|x| x.address()).collect(),
        entries: leaders
            .into_iter()
            .filter(|&n| reached[n])
            .map(|n| items[n].address())
            .collect(),
        padding: items
            .iter()
            .enumerate()
            .filter(|(n, _)| !reached[*n])
            .map(|(_, x)| x.address())
            .collect(),
        returns,
        blocks,
        edges,
    })
}

fn parity(bytes: &[u8], base: u64) -> bool {
    match (admit(bytes, base), old_admit(bytes, base)) {
        (Ok(actual), Ok(old)) => {
            assert_eq!(actual.entry(), old.entry());
            assert_eq!(actual.range(), old.range());
            assert_eq!(actual.heads(), old.heads());
            assert_eq!(actual.entries(), old.entries());
            assert_eq!(actual.padding_heads(), old.padding_heads());
            assert_eq!(actual.returns(), old.returns());
            assert_eq!(actual.blocks(), old.blocks());
            assert_eq!(actual.edges(), old.edges());
            true
        }
        (Err(actual), Err(old)) => {
            assert_eq!(actual, old);
            false
        }
        (actual, old) => panic!("parity for {bytes:02x?}: {actual:?} versus {old:?}"),
    }
}

#[test]
fn shared_cfg_preserves_complete_certificates_and_hostile_refusals() {
    const BASE: u64 = 0x1000;
    for (bytes, accepted) in [
        (&[0xc3][..], true),
        (&[0x90, 0x75, 0xfd, 0xc3][..], true),
        (&[0x75, 0xfe, 0xc3][..], false),
        (&[0x90, 0x90, 0x74, 0, 0xc3][..], true),
        (&[0x90, 0xeb, 1, 0x90, 0xc3][..], true),
        (&[0x90, 0xeb, 2, 0x31, 0xc0, 0xc3][..], false),
        (&[0xe8, 0xfb, 0x0f, 0, 0, 0xc3][..], false),
        (&[0xe2, 0, 0xc3][..], false),
        (&[0xe3, 0, 0xc3][..], false),
        (&[0xf3, 0xc3][..], false),
        (&[0x0f][..], false),
        (&[0xeb, 0xff][..], false),
        (&[0xeb, 0x7f][..], false),
        (&[0xeb, 2, 0x90, 0x90, 0xeb, 0xfa, 0xc3][..], false),
    ] {
        assert_eq!(parity(bytes, BASE), accepted, "{bytes:02x?}");
    }
    let duplicate = admit(&[0x90, 0x90, 0x74, 0, 0xc3], BASE).unwrap();
    assert_eq!(
        &duplicate.edges()[2..],
        &[(BASE + 2, BASE + 4), (BASE + 2, BASE + 4)]
    );
    let padding = admit(&[0x90, 0xeb, 1, 0x90, 0xc3], BASE).unwrap();
    assert_eq!(padding.padding_heads(), &[BASE + 3]);
    assert_eq!(padding.blocks(), &[(BASE, BASE + 3), (BASE + 4, BASE + 5)]);
    for returns in 1..=5 {
        let mut bytes = Vec::new();
        for _ in 1..returns {
            bytes.extend([0x74, 1, 0xc3]);
        }
        bytes.push(0xc3);
        assert_eq!(parity(&bytes, BASE), returns <= 4);
    }
    for branches in [30, 31, 32, 33] {
        let mut bytes = vec![0x90];
        for _ in 0..branches {
            bytes.extend([0x74, 0]);
        }
        bytes.push(0xc3);
        assert_eq!(parity(&bytes, BASE), branches < 32);
    }
    assert!(!parity(&[], BASE));
    assert!(!parity(&[0xc3], 0));
    assert!(!parity(&[0x90, 0xc3], u64::MAX - 1));
    let mut excessive = vec![0x90; 256];
    excessive.push(0xc3);
    assert!(!parity(&excessive, BASE));
}
