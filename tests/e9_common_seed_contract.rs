//! Pure contract checks; no process, mapping, decoder or workload.
#[path = "support/e9_common_seed.rs"]
pub mod seed;
use seed::*;

#[test]
fn exact_complete_inventory_and_range_owners_only() {
    assert!(authenticate(EXPECTED_INSTRUCTIONS, &ORIGINAL_RANGES).is_ok());
    let last_line = EXPECTED_INSTRUCTIONS[..EXPECTED_INSTRUCTIONS.len() - 1]
        .iter()
        .rposition(|&b| b == b'\n')
        .unwrap()
        + 1;
    for table in [
        b"".as_slice(),
        &EXPECTED_INSTRUCTIONS[..last_line],
        &EXPECTED_INSTRUCTIONS[..EXPECTED_INSTRUCTIONS.len() - 1],
    ] {
        assert!(matches!(
            authenticate(table, &ORIGINAL_RANGES),
            Err(Refusal::Inventory)
        ));
    }
    let mut altered = EXPECTED_INSTRUCTIONS.to_vec();
    let index = altered.iter().position(|&b| b == b'0').unwrap();
    altered[index] = b'1';
    assert!(matches!(
        authenticate(&altered, &ORIGINAL_RANGES),
        Err(Refusal::Inventory)
    ));
    assert!(matches!(
        authenticate(EXPECTED_INSTRUCTIONS, &ORIGINAL_RANGES[..2]),
        Err(Refusal::SourceRanges)
    ));
    let wrong = [
        SourceRange {
            function: Function::Store,
            pc: 0x401840,
            file_offset: 0x1840,
            bytes: b"\x48\x89\x14\xf7\x90",
        },
        SourceRange {
            ..ORIGINAL_RANGES[1]
        },
        SourceRange {
            ..ORIGINAL_RANGES[2]
        },
    ];
    assert!(matches!(
        authenticate(EXPECTED_INSTRUCTIONS, &wrong),
        Err(Refusal::SourceRanges)
    ));
}

#[test]
fn finite_case_domain_preserves_every_head_and_exact_call_return_words() {
    let inventory = authenticate(EXPECTED_INSTRUCTIONS, &ORIGINAL_RANGES).unwrap();
    let anchors = Anchors::new(0x30001000, 0x40008008).unwrap();
    let mut calls = 0;
    let mut faults = 0;
    let mut memory_cases = 0;
    for index in 0..CASE_COUNT {
        let case = inventory.case(index, anchors).unwrap();
        assert_eq!(case.head_index, if index < 174 { index / 2 } else { 0 });
        assert_eq!(case.state_index, index & 1);
        assert_eq!(case.stack.bytes.len(), STACK_BYTES);
        assert_eq!(case.compared_stack_start, anchors.frame_anchor() - 128);
        let head = HEADS[case.head_index];
        memory_cases += usize::from(case.memory_effect.is_some());
        if matches!(
            head.flow,
            Flow::Jb(_) | Flow::Jae(_) | Flow::Jbe(_) | Flow::Jne(_)
        ) && case.state_index == 0
        {
            let other = inventory.case(index + 1, anchors).unwrap();
            assert_ne!(case.completion, other.completion);
        }
        if let Flow::Call(to) = head.flow {
            calls += 1;
            let word = case.memory_effect.unwrap();
            assert_eq!(word.bytes, (head.pc + 5).to_le_bytes());
            assert_eq!(
                case.completion,
                Completion::OriginalPc {
                    pc: to,
                    rsp: case.registers.get(Reg::Rsp) - 8
                }
            );
        }
        if let Completion::Fault {
            pc,
            address,
            signal,
            code,
            ..
        } = case.completion
        {
            faults += 1;
            assert_eq!((pc, signal, code), (0x401840, 11, 2));
            assert_eq!(address, anchors.data_address() + [8, 24][case.state_index]);
            assert_eq!(case.data.region.permissions, Permissions::Read);
        }
    }
    assert_eq!((calls, faults), (12, 2));
    assert_eq!(memory_cases, 32 * 2 + 2);
    assert_eq!(
        HEADS
            .iter()
            .filter(|h| !h.entry_reachable)
            .map(|h| (h.pc, h.seed_rsp_minus_e))
            .collect::<Vec<_>>(),
        vec![(0x40186e, -40), (0x40194d, 0)]
    );
    assert!(matches!(
        inventory.case(CASE_COUNT, anchors),
        Err(Refusal::CaseIndex)
    ));
}

#[test]
fn invalid_anchor_domains_are_refused_before_seed_construction() {
    let low_end = 0x0000_8000_0000_0000;
    for (a, e) in [
        (1, 0x40008008),
        (0x30001000, 0x40008000),
        (0, 8),
        (low_end - 4096, 0x40008008),
        (0x30001000, low_end - 4088),
        (0x30001000, 0x30001008),
        (0x401000, 0x40008008),
    ] {
        assert_eq!(Anchors::new(a, e), Err(Refusal::Anchors));
    }
}
