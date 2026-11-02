//! Literal predecessor reference and additive shared-CFG parity controls.
use super::*;
use std::collections::BTreeSet;

fn old_derive_blocks(
    function: AddressRange,
    scan: &ScanResult,
) -> Result<Vec<AddressRange>, Error> {
    let heads: BTreeSet<_> = scan.instructions().iter().map(|i| i.address()).collect();
    let mut boundaries = BTreeSet::from([function.start(), function.end()]);
    for item in scan.instructions() {
        let instruction = item.instruction();
        let next = instruction.next_ip();
        let flow = instruction.flow_control();
        if flow != FlowControl::Next && next < function.end() {
            boundaries.insert(next);
        }
        let mut successors = Vec::new();
        match flow {
            FlowControl::Next => successors.push(next),
            FlowControl::Call if instruction.code() == Code::Call_rel32_64 => {
                // The unchanged call target is not an inferred victim owner.
                // Only its local continuation contributes to this partition.
                successors.push(next);
            }
            FlowControl::Return if instruction.code() == Code::Retnq => {}
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch => {
                if !matches!(
                    instruction.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                ) {
                    return Err(Error::new("neighbor-non-near-branch", item.address()));
                }
                let target = instruction.near_branch_target();
                boundaries.insert(target);
                successors.push(target);
                if flow == FlowControl::ConditionalBranch {
                    successors.push(next);
                }
            }
            _ => return Err(Error::new("neighbor-control-flow", item.address())),
        }
        if successors.iter().any(|pc| !heads.contains(pc)) {
            return Err(Error::new("neighbor-target-not-head", item.address()));
        }
    }
    let boundaries: Vec<_> = boundaries.into_iter().collect();
    boundaries
        .windows(2)
        .map(|pair| addr(pair[0], pair[1] - pair[0]))
        .collect()
}

#[test]
fn shared_neighbor_graph_preserves_broad_transfer_forms_and_first_errors() {
    const BASE: u64 = 0x1000;
    for (bytes, accepted) in [
        (&[0x74, 1, 0x90, 0xc3][..], true),
        (&[0x90, 0x90, 0x74, 0, 0xc3][..], true),
        (&[0x90, 0xeb, 1, 0x90, 0xc3][..], true),
        (&[0x90, 0xeb, 2, 0x31, 0xc0, 0xc3][..], true),
        (&[0xe8, 0xfb, 0x0f, 0, 0, 0xc3][..], true),
        (&[0xe8, 0xfb, 0xff, 0xff, 0xff, 0xc3][..], true),
        (&[0xe8, 0xfb, 0x0f, 0, 0][..], false),
        (&[0xe2, 0, 0xc3][..], true),
        (&[0xe3, 0, 0xc3][..], true),
        (&[0xf3, 0xc3][..], true),
        (&[0x75, 0xfe, 0xc3][..], true),
        (&[0xeb, 0xff][..], false),
        (&[0xeb, 0x7f][..], false),
        (&[0x74, 0][..], false),
        (&[0xff, 0xe0][..], false),
        (&[0xff, 0xd0, 0xc3][..], false),
        (&[0xeb, 0x7f, 0xff, 0xe0, 0xc3][..], false),
        (&[0xff, 0xe0, 0xeb, 0x7f, 0xc3][..], false),
    ] {
        let function = AddressRange::new(BASE, bytes.len()).unwrap();
        let scan = InstructionScanner::default().scan(bytes, BASE).unwrap();
        let actual = derive_blocks(function, &scan);
        assert_eq!(actual, old_derive_blocks(function, &scan), "{bytes:02x?}");
        assert_eq!(actual.is_ok(), accepted, "{bytes:02x?}");
    }
    for (bytes, stage) in [
        (
            &[0xeb, 0x7f, 0xff, 0xe0, 0xc3][..],
            "neighbor-target-not-head",
        ),
        (&[0xff, 0xe0, 0xeb, 0x7f, 0xc3][..], "neighbor-control-flow"),
    ] {
        let scan = InstructionScanner::default().scan(bytes, BASE).unwrap();
        assert_eq!(
            derive_blocks(AddressRange::new(BASE, bytes.len()).unwrap(), &scan),
            Err(Error::new(stage, BASE))
        );
    }
    let bytes = [0x90, 0xeb, 1, 0x90, 0xc3];
    let scan = InstructionScanner::default().scan(&bytes, BASE).unwrap();
    assert_eq!(
        derive_blocks(AddressRange::new(BASE, bytes.len()).unwrap(), &scan).unwrap(),
        [
            addr(BASE, 3).unwrap(),
            addr(BASE + 3, 1).unwrap(),
            addr(BASE + 4, 1).unwrap()
        ]
    );
}
