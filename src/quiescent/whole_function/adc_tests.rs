//! Additive complete-region ADC checks; no publication or candidate execution.
use super::*;

#[allow(dead_code)]
#[path = "../../../tests/support/adc_fixtures.rs"]
mod adc;

// Exact retained GCC bodies. No padding, split extent or rewritten fixture.
const FIRST_EQUAL: &[u8] = &[
    0x48, 0x89, 0xf0, 0x48, 0x85, 0xf6, 0x74, 0x1a, 0x31, 0xd2, 0xeb, 0x0d, 0x0f, 0x1f, 0x40, 0x00,
    0x48, 0x83, 0xc2, 0x01, 0x48, 0x39, 0xd0, 0x74, 0x0f, 0x80, 0x3c, 0x17, 0x3d, 0x75, 0xf1, 0x48,
    0x89, 0xd0, 0xc3, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0xc3,
];
const UPPERCASE: &[u8] = &[
    0x48, 0x85, 0xf6, 0x74, 0x2b, 0x48, 0x01, 0xfe, 0x45, 0x31, 0xc0, 0x0f, 0x1f, 0x44, 0x00, 0x00,
    0x0f, 0xb6, 0x07, 0x83, 0xe8, 0x41, 0x3c, 0x1a, 0x49, 0x83, 0xd0, 0x00, 0x48, 0x83, 0xc7, 0x01,
    0x48, 0x39, 0xf7, 0x75, 0xeb, 0x4c, 0x89, 0xc0, 0xc3, 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x45, 0x31, 0xc0, 0x4c, 0x89, 0xc0, 0xc3,
];

fn upper() -> Fixture {
    Fixture::new(UPPERCASE, &[0, 5, 16, 37, 48], &[40, 54])
}

#[test]
fn whole_adc_actual_compiled_bodies_keep_every_head_return_and_exact_byte() {
    type CompiledCase = (
        &'static [u8],
        &'static [u64],
        &'static [u64],
        &'static [u64],
    );
    let cases: [CompiledCase; 2] = [
        (
            FIRST_EQUAL,
            &[0, 8, 16, 25, 31, 34, 40],
            &[34, 40],
            &[0, 3, 6, 8, 10, 12, 16, 20, 23, 25, 29, 31, 34, 35, 40],
        ),
        (
            UPPERCASE,
            &[0, 5, 16, 37, 48],
            &[40, 54],
            &[
                0, 3, 5, 8, 11, 16, 19, 22, 24, 28, 32, 35, 37, 40, 41, 48, 51, 54,
            ],
        ),
    ];
    for (bytes, leaders, returns, heads) in cases {
        let f = Fixture::new(bytes, leaders, returns);
        let proof = f.proof().unwrap();
        let scan = f.scan();
        let plan = f.plan();
        let parts = plan.plan().parts();
        assert_eq!(parts.displaced, range(PC, bytes.len()));
        assert_eq!(
            parts.reads,
            [ExpectedBytes {
                address: PC,
                bytes: bytes.to_vec()
            }]
        );
        assert_eq!(parts.entries, f.entries);
        assert_eq!(parts.writes.len(), 1);
        assert_eq!(parts.writes[0].address, PC);
        assert_eq!(parts.writes[0].bytes.len(), bytes.len());
        assert_eq!(parts.allocations.len(), 1);
        assert!(parts.allocations[0].range.len() <= 8192);
        assert_eq!(plan.image().controls().len(), 3);
        assert_eq!(
            plan.image()
                .instruction_boundaries()
                .iter()
                .map(|&(pc, _)| pc)
                .collect::<Vec<_>>(),
            heads.iter().map(|offset| PC + offset).collect::<Vec<_>>()
        );
        assert_eq!(
            plan.image()
                .entry_routes()
                .iter()
                .map(|&(pc, _)| pc)
                .collect::<Vec<_>>(),
            heads.iter().map(|offset| PC + offset).collect::<Vec<_>>()
        );
        assert_eq!(
            plan.image().controls(),
            f.actions
                .iter()
                .map(|a| a.control.clone())
                .collect::<Vec<_>>()
        );
        proof.verify_image(&scan, &f.actions, plan.image()).unwrap();
        assert_eq!(plan.metrics().displaced_bytes, bytes.len());
        assert_eq!(plan.metrics().attempts.len(), 1);
    }
}

#[test]
fn whole_adc_all_31_forms_and_186_operand_fixtures_use_exact_scalar_guard() {
    let mut families = 0;
    let mut bodies = 0;
    for width in [8, 16, 32, 64] {
        for form in adc::forms(width) {
            families += 1;
            for (_, right) in adc::operands(width, form) {
                let instruction = adc::instruction(width, form, right);
                let mut body = instruction.clone();
                body.extend([0x90, 0x90, 0x90, 0xc3]);
                let ret = (body.len() - 1) as u64;
                let f = Fixture::new(&body, &[0], &[ret]);
                f.proof()
                    .unwrap_or_else(|e| panic!("{width}/{form:?}/{right:#x}: {e:?}"));
                assert_eq!(
                    f.scan().instructions()[0].instruction().mnemonic(),
                    Mnemonic::Adc
                );
                assert_eq!(f.scan().instructions()[0].len(), instruction.len());
                assert_eq!(
                    f.actions.iter().map(|a| a.logical_pc).collect::<Vec<_>>(),
                    [PC, PC + ret]
                );
                bodies += 1;
            }
        }
    }
    assert_eq!(families, 31);
    assert_eq!(bodies, 186);
}

fn scalar_refuses(instruction: &[u8]) {
    let mut bytes = instruction.to_vec();
    bytes.extend([0x90, 0x90, 0xc3]);
    let f = Fixture::new(&bytes, &[0], &[(bytes.len() - 1) as u64]);
    // The scanner must accept the complete instruction first. The unchanged
    // general qualifier or stricter closed-scalar guard must then refuse it.
    assert!(
        matches!(f.proof(), Err(Refusal::UnsupportedSemantics(_))),
        "{instruction:02x?}"
    );
}

#[test]
fn whole_adc_rejects_callee_saved_stack_segment_and_nonlocal_address_forms() {
    for instruction in [
        &[0x48, 0x13, 0xd8][..],               // RBX destination
        &[0x48, 0x13, 0xc3],                   // RBX source
        &[0x4c, 0x13, 0xe0],                   // R12 destination
        &[0x49, 0x13, 0xc4],                   // R12 source
        &[0x48, 0x13, 0xe0],                   // RSP destination
        &[0x48, 0x13, 0xc4],                   // RSP source
        &[0x12, 0xc7],                         // BH source
        &[0x12, 0xf8],                         // BH destination
        &[0x48, 0x13, 0x04, 0x24],             // [RSP]
        &[0x48, 0x13, 0x45, 0],                // [RBP]
        &[0x48, 0x13, 0x03],                   // [RBX]
        &[0x49, 0x13, 0x04, 0x24],             // [R12]
        &[0x4a, 0x13, 0x04, 0x27],             // [RDI+R12]
        &[0x48, 0x13, 0x05, 0, 0, 0, 0],       // RIP-relative
        &[0x48, 0x13, 0x04, 0x25, 0, 0, 0, 0], // Absolute, no base
        &[0x67, 0x48, 0x13, 0x07],             // Address32
        &[0x64, 0x48, 0x13, 0x07],             // FS
        &[0x65, 0x48, 0x13, 0x07],             // GS
        &[0x2e, 0x48, 0x13, 0x07],             // Explicit CS
    ] {
        scalar_refuses(instruction);
    }
}

#[test]
fn whole_adc_rejects_writes_prefixes_adx_and_control_transfers() {
    for instruction in [
        &[0x10, 0x07][..],
        &[0x66, 0x11, 0x07],
        &[0x11, 0x07],
        &[0x48, 0x11, 0x07],
        &[0x80, 0x17, 1],
        &[0x48, 0x83, 0x17, 1],
        &[0xf0, 0x48, 0x11, 0x07],
        &[0xf2, 0x48, 0x13, 0xc1],
        &[0xf3, 0x48, 0x13, 0xc1],
        &[0x66, 0x0f, 0x38, 0xf6, 0xc1], // ADCX
        &[0xf3, 0x0f, 0x38, 0xf6, 0xc1], // ADOX
        &[0x48, 0x83, 0xd0, 0, 0xff, 0xd0],
        &[0x48, 0x83, 0xd0, 0, 0x0f, 0x05],
        &[0x48, 0x83, 0xd0, 0, 0xc2, 8, 0],
    ] {
        scalar_refuses(instruction);
    }
}

#[test]
fn whole_adc_keeps_reachability_complete_roles_and_boundaries_mandatory() {
    for bytes in [
        &[0xc3, 0x48, 0x83, 0xd0, 0, 0xc3][..],
        &[0xeb, 4, 0x48, 0x83, 0xd0, 0, 0xc3],
        &[0x48, 0x83, 0xd0, 0, 0xeb, 0xfb, 0xc3],
        &[0x48, 0x83, 0xd0, 0, 0xeb, 0x7f, 0xc3],
        &[0x48, 0x83, 0xd0, 0, 0xeb, 0xfa, 0xc3],
        &[0x48, 0x83, 0xd0, 0, 0x90],
    ] {
        let f = Fixture::new(bytes, &[0], &[(bytes.len() - 1) as u64]);
        assert_eq!(f.proof().unwrap_err(), unsupported(), "{bytes:02x?}");
    }
    for change in 0..4 {
        let mut f = upper();
        match change {
            0 => {
                f.actions.pop();
            }
            1 => f.actions.swap(1, 2),
            2 => f.actions[2].control = f.actions[1].control.clone(),
            3 => f.actions[1].logical_pc -= 1,
            _ => unreachable!(),
        }
        assert_eq!(f.proof().unwrap_err(), Refusal::InvalidPlan);
    }
    for change in 0..4 {
        let mut f = upper();
        match change {
            0 => {
                f.entries.entries.pop();
            }
            1 => f.entries.completeness = EntryCompleteness::AllInstructionHeads,
            2 => f.entries.resumes = ResumeObligation::Enumerated(vec![PC + 24]),
            3 => f.entries.entries[0].requires_endbr = true,
            _ => unreachable!(),
        }
        assert_eq!(f.proof().unwrap_err(), Refusal::UnresolvedEntry);
    }
}

#[test]
fn whole_adc_preserves_80_byte_and_allocation_caps_and_exact_overlay() {
    for (length, accepted) in [(80, true), (81, false)] {
        let mut body = vec![0x48, 0x83, 0xd0, 0];
        body.resize(length - 1, 0x90);
        body.push(0xc3);
        let f = Fixture::new(&body, &[0], &[(length - 1) as u64]);
        if accepted {
            f.proof().unwrap();
        } else {
            assert_eq!(f.proof().unwrap_err(), Refusal::NoPatchWindow);
        }
    }
    for change in 0..3 {
        let mut f = upper();
        match change {
            0 => f.allocation.max_candidates = 257,
            1 => f.allocation.max_mappings = 2,
            2 => f.allocation.max_mapped_bytes = 8193,
            _ => unreachable!(),
        }
        assert_eq!(f.proof().unwrap_err(), Refusal::AllocationUnavailable);
    }
    let f = upper();
    let mut changed = UPPERCASE.to_vec();
    changed[26] ^= 1;
    let prior = Composition::new(
        f.entries.identity,
        vec![ExpectedBytes {
            address: PC,
            bytes: changed,
        }],
    )
    .unwrap();
    // SAFETY: source-only invalid overlay; no code is published or executed.
    let failure =
        unsafe { plan_whole_function_controlled_detailed_after(&f.request(), &f.actions, &prior) }
            .unwrap_err();
    assert_eq!(failure.reason, Refusal::ExpectedBytesChanged);
    assert!(failure.attempts.is_empty());
    assert!(!failure.search.accepted);
}

#[test]
fn whole_adc_malformed_encoding_refuses_before_any_image_attempt() {
    for bytes in [
        &[0x90, 0x90, 0x90, 0x48, 0x13][..], // Missing ModRM.
        &[0x90, 0x48, 0x81, 0xd0, 0],        // Truncated immediate32.
        &[0xf0, 0x48, 0x13, 0xc1, 0xc3],     // LOCK on register ADC.
    ] {
        let f = Fixture::new(bytes, &[0], &[(bytes.len() - 1) as u64]);
        // SAFETY: invalid source-only fixture; no image may be published.
        let failure = unsafe { plan_whole_function_controlled_detailed(&f.request(), &f.actions) }
            .unwrap_err();
        assert!(
            matches!(failure.reason, Refusal::Backend(_)),
            "{bytes:02x?}"
        );
        assert!(failure.attempts.is_empty());
        assert!(!failure.search.accepted);
    }
}
