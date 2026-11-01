use super::*;

#[test]
fn literal_add_fixture_and_complete_argument_sum_agree() {
    use iced_x86::{Mnemonic, Register};
    let scan = InstructionScanner::default().scan(&CODE, 0x1000).unwrap();
    let instructions = scan.instructions();
    assert_eq!(instructions.len(), 3);
    assert_eq!(
        instructions.iter().map(|i| i.address()).collect::<Vec<_>>(),
        [0x1000, 0x1003, 0x1006]
    );
    assert_eq!(
        instructions
            .iter()
            .map(|i| i.instruction().mnemonic())
            .collect::<Vec<_>>(),
        [Mnemonic::Mov, Mnemonic::Add, Mnemonic::Ret]
    );
    assert_eq!(
        (
            instructions[0].instruction().op0_register(),
            instructions[0].instruction().op1_register()
        ),
        (Register::RAX, Register::RDI)
    );
    assert_eq!(
        (
            instructions[1].instruction().op0_register(),
            instructions[1].instruction().op1_register()
        ),
        (Register::RAX, Register::RSI)
    );
    let mut expected = 0_u128;
    for i in 0..CALLS {
        let (a, b) = inputs(i);
        let value = u128::from(a) + u128::from(b);
        assert_eq!(value, 3 * u128::from(i) + 4);
        expected += value;
    }
    assert_eq!(expected, 6_296_576);
    assert_eq!(u128::from(CHECKSUM), expected);
    assert_eq!(5 + 3 * (3 + 64), 206);
    assert_eq!(2 + (3 + 9 + 192) * CALLS, 417_794);
}

#[test]
fn every_distinct_order_keeps_enabled_controls_and_full_timed_denominator() {
    let mut permutations = 0;
    for a in Arm::ALL {
        for b in Arm::ALL {
            for c in Arm::ALL {
                if a == b || a == c || b == c {
                    continue;
                }
                let text = [a, b, c].map(|arm| arm.name(false)).join(",");
                let ordered = order(&text);
                assert_eq!(ordered, [a, b, c]);
                let rows = roster(ordered);
                assert_eq!(rows.len(), 206);
                assert_eq!(
                    (rows[0].arm, rows[0].phase, rows[1].arm, rows[1].phase),
                    (
                        Arm::Ordinary,
                        "enabled-control",
                        Arm::Early,
                        "enabled-control"
                    )
                );
                assert_eq!(
                    rows[2..5].iter().map(|r| r.arm).collect::<Vec<_>>(),
                    Arm::ALL
                );
                assert!(
                    rows.iter()
                        .all(|r| r.status == "UNOBSERVED" && r.result.is_none())
                );
                for (part, arm) in rows[5..].chunks_exact(67).zip(ordered) {
                    assert!(part.iter().all(|r| r.arm == arm));
                    assert_eq!(part.iter().filter(|r| r.phase == "warmup").count(), 3);
                    assert_eq!(part.iter().filter(|r| r.phase == "measured").count(), 64);
                    assert_eq!(
                        part[3..].iter().map(|r| r.index).collect::<Vec<_>>(),
                        (0..64).collect::<Vec<_>>()
                    );
                }
                permutations += 1;
            }
        }
    }
    assert_eq!(permutations, 6);
    for invalid in [
        "native,ordinary-disabled,ordinary-disabled",
        "native,ordinary-enabled,early-disabled",
        "native,ordinary-disabled",
        "native,ordinary-disabled,early-disabled,extra",
    ] {
        assert!(std::panic::catch_unwind(|| order(invalid)).is_err());
    }
}

#[test]
fn csv_preserves_failed_and_dispatched_rows_without_invented_measurements() {
    let mut rows = roster(Arm::ALL);
    rows[0].status = "PASS";
    rows[0].result = Some(ResultRow {
        elapsed: None,
        checksum: 18,
        callbacks: 1,
        records: 1,
        refusals: 0,
    });
    rows[1].status = "FAILED";
    rows[2].status = "DISPATCHED";
    let rendered = render(&rows, 7);
    let lines: Vec<_> = rendered.lines().collect();
    assert_eq!(lines.len(), 207);
    assert_eq!(lines[0].split(',').count(), 13);
    assert_eq!(
        &lines[1].split(',').collect::<Vec<_>>()[2..],
        &[
            "7",
            "ordinary-enabled",
            "enabled-control",
            "0",
            "PASS",
            "1",
            "",
            "18",
            "1",
            "1",
            "0"
        ]
    );
    for (line, expected) in [(2, "FAILED"), (3, "DISPATCHED"), (4, "UNOBSERVED")] {
        let fields: Vec<_> = lines[line].split(',').collect();
        assert_eq!(fields.len(), 13);
        assert_eq!(fields[6], expected);
        assert!(fields[8..].iter().all(|s| s.is_empty()));
    }
    assert_eq!(rows[3].phase, "qualification");
}
