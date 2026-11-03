use super::*;
use crate::scanner::InstructionScanner;

const BASE: u64 = 0x1000;

fn scan(bytes: &[u8]) -> ScanResult {
    InstructionScanner::default().scan(bytes, BASE).unwrap()
}

#[test]
fn local_edges_keep_callees_multiplicity_and_padding_partitions_distinct() {
    let source = scan(&[0xe8, 0xfb, 0x0f, 0, 0, 0xc3]);
    let graph = build(&source, |_, _, _| Ok::<_, ()>(())).unwrap();
    let row = graph.row(0).unwrap();
    assert_eq!(row.call_target(), Some(0x2000));
    assert_eq!(row.continuation(), Some(Target::Head(1)));
    assert_eq!(row.successors(), &[Target::Head(1)]);
    assert!(!row.unresolved_transfer());
    assert_eq!(graph.branch_entries(), &BTreeSet::from([0]));
    let indexed = graph.indexed().unwrap();
    assert_eq!(indexed.successors(), &[vec![1], vec![]]);
    assert_eq!(indexed.reachable_from(0).unwrap(), [true, true]);
    assert_eq!(indexed.can_reach_any(&[1]).unwrap(), [true, true]);

    let source = scan(&[0x90, 0x90, 0x74, 0, 0xc3]);
    let graph = build(&source, |_, _, _| Ok::<_, ()>(())).unwrap();
    assert_eq!(
        graph.row(2).unwrap().successors(),
        &[Target::Head(3), Target::Head(3)]
    );
    assert_eq!(graph.indexed().unwrap().successors()[2], [3, 3]);
    assert_eq!(graph.branch_entries(), &BTreeSet::from([0, 3]));

    let source = scan(&[0x90, 0xeb, 1, 0x90, 0xc3]);
    let graph = build(&source, |_, _, _| Ok::<_, ()>(())).unwrap();
    let indexed = graph.indexed().unwrap();
    let reached = indexed.reachable_from(0).unwrap();
    assert_eq!(reached, [true, true, false, true]);
    assert_eq!(graph.branch_entries(), &BTreeSet::from([0, 3]));
    assert_eq!(
        indexed.blocks(Coverage::Reachable(&reached)).unwrap(),
        [(BASE, BASE + 3), (BASE + 4, BASE + 5)]
    );
    assert_eq!(
        indexed
            .blocks(Coverage::AllDecoded(AddressRange::new(BASE, 5).unwrap()))
            .unwrap(),
        [(BASE, BASE + 3), (BASE + 3, BASE + 4), (BASE + 4, BASE + 5)]
    );
}

#[test]
fn unresolved_rows_and_public_dimensions_refuse_without_reordering_callbacks() {
    for bytes in [&[0xff, 0xe0][..], &[0xff, 0xd0, 0xc3], &[0x0f, 0x05]] {
        let source = scan(bytes);
        let graph = build(&source, |_, _, _| Ok::<_, ()>(())).unwrap();
        assert!(graph.row(0).unwrap().unresolved_transfer());
        assert_eq!(
            graph.indexed().unwrap_err(),
            GraphError::UnresolvedTransfer(0)
        );
    }
    let source = scan(&[0xeb, 0x7f]);
    let graph = build(&source, |_, _, _| Ok::<_, ()>(())).unwrap();
    assert_eq!(
        graph.row(0).unwrap().branch_target(),
        Some(Target::NotHead(BASE + 129))
    );
    assert_eq!(
        graph.indexed().unwrap_err(),
        GraphError::UnresolvedTarget(0, BASE + 129)
    );

    let source = scan(&[0xc3]);
    let graph = build(&source, |_, _, _| Ok::<_, ()>(())).unwrap();
    let indexed = graph.indexed().unwrap();
    assert!(graph.row(0).unwrap().successors().is_empty());
    assert!(!graph.row(0).unwrap().unresolved_transfer());
    assert!(graph.row(1).is_none());
    assert_eq!(indexed.reachable_from(1), Err(GraphError::InvalidIndex(1)));
    assert_eq!(
        indexed.can_reach_any(&[0, 1]),
        Err(GraphError::InvalidIndex(1))
    );
    for mask in [&[][..], &[true, false]] {
        assert_eq!(
            indexed.blocks(Coverage::Reachable(mask)),
            Err(GraphError::CoverageLength)
        );
    }
    let source = ScanResult::default();
    let graph = build(&source, |_, _, _| -> Result<(), ()> {
        panic!("empty scan callback")
    })
    .unwrap();
    assert!(graph.branch_entries().is_empty());
    let indexed = graph.indexed().unwrap();
    assert_eq!(indexed.reachable_from(0), Err(GraphError::InvalidIndex(0)));
    assert!(indexed.can_reach_any(&[]).unwrap().is_empty());
    assert!(indexed.blocks(Coverage::Reachable(&[])).unwrap().is_empty());

    let source = scan(&[0x0f, 0xa2, 0xeb, 0x7f, 0xc3]);
    let mut visited = Vec::new();
    let result = build(&source, |index, _, _| {
        visited.push(index);
        Err("original first refusal")
    });
    assert_eq!(result.unwrap_err(), "original first refusal");
    assert_eq!(visited, [0]);
    let source = scan(&[0xeb, 1, 0x90, 0xc3]);
    let mut visited = Vec::new();
    let result = build(&source, |index, _, _| {
        visited.push(index);
        if index == 1 {
            Err("unreachable row still checked")
        } else {
            Ok(())
        }
    });
    assert_eq!(result.unwrap_err(), "unreachable row still checked");
    assert_eq!(visited, [0, 1]);
}

#[test]
fn shared_cut_collector_keeps_global_direct_facts_separate_from_local_edges() {
    // CALL 0x2000; XBEGIN BASE+12; NOP; RET. The CALL is external to this
    // scan; XBEGIN has a near operand but is not a local branch-row category.
    let source = scan(&[0xe8, 0xfb, 0x0f, 0, 0, 0xc7, 0xf8, 1, 0, 0, 0, 0x90, 0xc3]);
    let items = source.instructions();
    assert_eq!(direct_target(items[0].instruction()), Some(0x2000));
    assert_eq!(direct_target(items[1].instruction()), Some(BASE + 12));
    assert_eq!(direct_target(items[2].instruction()), None);
    assert_eq!(direct_target(items[3].instruction()), None);
    let owner = AddressRange::new(BASE, 13).unwrap();
    let mut visited = Vec::new();
    let cuts = collect_block_cuts(
        [owner],
        items.iter().map(|item| item.instruction()),
        |_, _| true,
        |index, target| {
            visited.push((index, target));
            Ok::<_, ()>(true)
        },
    )
    .unwrap();
    assert_eq!(visited, [(0, 0x2000), (1, BASE + 12)]);
    assert_eq!(
        cuts,
        BTreeSet::from([BASE, BASE + 5, BASE + 11, BASE + 12, BASE + 13, 0x2000])
    );

    let graph = build(&source, |_, _, _| Ok::<_, ()>(())).unwrap();
    assert_eq!(graph.row(0).unwrap().call_target(), Some(0x2000));
    assert!(graph.row(1).unwrap().unresolved_transfer());
    let mut local_callbacks = Vec::new();
    assert_eq!(
        graph.block_cuts(owner, |index| {
            local_callbacks.push(index);
            true
        }),
        BTreeSet::from([BASE, BASE + 5, BASE + 11, BASE + 13])
    );
    assert!(local_callbacks.is_empty()); // Neither CALL nor XBEGIN is relabeled.

    // Defensive raw-operand coverage; no claim that default 64-bit decoding
    // produces a 16/32-bit CALL operand for these bytes.
    for kind in [
        OpKind::NearBranch16,
        OpKind::NearBranch32,
        OpKind::NearBranch64,
    ] {
        let mut instruction = *items[0].instruction();
        instruction.set_op0_kind(kind);
        match kind {
            OpKind::NearBranch16 => instruction.set_near_branch16(0x2000),
            OpKind::NearBranch32 => instruction.set_near_branch32(0x2000),
            OpKind::NearBranch64 => instruction.set_near_branch64(0x2000),
            _ => unreachable!(),
        }
        assert_eq!(direct_target(&instruction), Some(0x2000));
    }
}

#[test]
fn shared_cut_collector_preserves_policy_order_and_first_error() {
    let source = scan(&[0xe8, 0xfb, 0x0f, 0, 0, 0xeb, 0, 0xc3]);
    let events = std::cell::RefCell::new(Vec::new());
    let result = collect_block_cuts(
        [AddressRange::new(BASE, 8).unwrap()],
        source.instructions().iter().map(|item| item.instruction()),
        |index, next| {
            events.borrow_mut().push(("following", index, next));
            true
        },
        |index, target| {
            events.borrow_mut().push(("direct", index, target));
            Err::<bool, _>("first global target refusal")
        },
    );
    assert_eq!(result, Err("first global target refusal"));
    assert_eq!(
        events.into_inner(),
        [("following", 0, BASE + 5), ("direct", 0, 0x2000)]
    );

    let source = scan(&[0xff, 0xd0, 0xff, 0xe0, 0xc3]);
    let cuts = collect_block_cuts(
        [AddressRange::new(BASE, 5).unwrap()],
        source.instructions().iter().map(|item| item.instruction()),
        |_, _| true,
        |_, _| -> Result<bool, ()> { panic!("indirect transfer has no direct operand") },
    )
    .unwrap();
    assert_eq!(cuts, BTreeSet::from([BASE, BASE + 2, BASE + 4, BASE + 5]));
}
