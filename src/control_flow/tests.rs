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
