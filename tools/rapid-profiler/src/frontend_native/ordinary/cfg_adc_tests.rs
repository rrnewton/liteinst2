//! Additive ADC admission controls. No loader, executable mappings or execution.
use super::super::{TrustedFunctionSelection, selection};
use super::{SetupRefusal, admit};

#[allow(dead_code)]
#[path = "../../../../../tests/support/adc_fixtures.rs"]
mod adc;

const BASE: u64 = 0x1030;
// Exact GCC-produced 55-byte uppercase_count from the retained failed campaign.
// Heads/edges below are independently transcribed from that complete body.
const UPPERCASE: [u8; 55] = [
    0x48, 0x85, 0xf6, 0x74, 0x2b, 0x48, 0x01, 0xfe, 0x45, 0x31, 0xc0, 0x0f, 0x1f, 0x44, 0x00, 0x00,
    0x0f, 0xb6, 0x07, 0x83, 0xe8, 0x41, 0x3c, 0x1a, 0x49, 0x83, 0xd0, 0x00, 0x48, 0x83, 0xc7, 0x01,
    0x48, 0x39, 0xf7, 0x75, 0xeb, 0x4c, 0x89, 0xc0, 0xc3, 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x45, 0x31, 0xc0, 0x4c, 0x89, 0xc0, 0xc3,
];
const FIRST_EQUAL: [u8; 41] = [
    0x48, 0x89, 0xf0, 0x48, 0x85, 0xf6, 0x74, 0x1a, 0x31, 0xd2, 0xeb, 0x0d, 0x0f, 0x1f, 0x40, 0x00,
    0x48, 0x83, 0xc2, 0x01, 0x48, 0x39, 0xd0, 0x74, 0x0f, 0x80, 0x3c, 0x17, 0x3d, 0x75, 0xf1, 0x48,
    0x89, 0xd0, 0xc3, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0xc3,
];

#[test]
fn exact_compiled_adc_body_has_complete_heads_edges_padding_and_two_returns() {
    let c = admit(&UPPERCASE, BASE).unwrap();
    assert_eq!(c.range(), (BASE, BASE + 55));
    assert_eq!(
        c.heads(),
        [
            0, 3, 5, 8, 11, 16, 19, 22, 24, 28, 32, 35, 37, 40, 41, 48, 51, 54
        ]
        .map(|offset| BASE + offset)
    );
    assert_eq!(c.entries(), [0, 5, 16, 37, 48].map(|offset| BASE + offset));
    assert_eq!(c.returns(), &[BASE + 40, BASE + 54]);
    assert_eq!(c.padding_heads(), &[BASE + 41]);
    assert_eq!(
        c.blocks(),
        [(0, 5), (5, 16), (16, 37), (37, 41), (48, 55)]
            .map(|(start, end)| (BASE + start, BASE + end))
    );
    assert_eq!(
        c.edges(),
        [
            (0, 3),
            (3, 48),
            (3, 5),
            (5, 8),
            (8, 11),
            (11, 16),
            (16, 19),
            (19, 22),
            (22, 24),
            (24, 28),
            (28, 32),
            (32, 35),
            (35, 16),
            (35, 37),
            (37, 40),
            (48, 51),
            (51, 54),
        ]
        .map(|(from, to)| (BASE + from, BASE + to))
    );
}

#[test]
fn every_scalar_adc_encoding_family_keeps_the_same_single_return_cfg() {
    let mut families = 0;
    let mut bodies = 0;
    for width in [8, 16, 32, 64] {
        for form in adc::forms(width) {
            families += 1;
            for (_, right) in adc::operands(width, form) {
                let mut bytes = adc::instruction(width, form, right);
                let ret = BASE + bytes.len() as u64;
                bytes.push(0xc3);
                let c = admit(&bytes, BASE)
                    .unwrap_or_else(|error| panic!("{width} {form:?} {right:#x}: {error:?}"));
                assert_eq!(c.range(), (BASE, ret + 1));
                assert_eq!(c.heads(), &[BASE, ret]);
                assert_eq!(c.entries(), &[BASE]);
                assert_eq!(c.returns(), &[ret]);
                assert!(c.padding_heads().is_empty());
                assert_eq!(c.blocks(), &[(BASE, ret + 1)]);
                assert_eq!(c.edges(), &[(BASE, ret)]);
                bodies += 1;
            }
        }
    }
    assert_eq!(families, 31);
    assert_eq!(bodies, 186);
}

fn refuses(prefix: &[u8]) {
    let mut bytes = prefix.to_vec();
    bytes.push(0xc3);
    assert_eq!(
        admit(&bytes, BASE).err(),
        Some(SetupRefusal::EntryExit),
        "{prefix:02x?}"
    );
}

#[test]
fn adc_never_admits_callee_saved_stack_segment_or_nonlocal_addresses() {
    for instruction in [
        &[0x48, 0x13, 0xd8][..],               // ADC RBX,RAX
        &[0x48, 0x13, 0xc3],                   // ADC RAX,RBX
        &[0x4c, 0x13, 0xe0],                   // ADC R12,RAX
        &[0x49, 0x13, 0xc4],                   // ADC RAX,R12
        &[0x48, 0x13, 0xe0],                   // ADC RSP,RAX
        &[0x48, 0x13, 0xc4],                   // ADC RAX,RSP
        &[0x12, 0xc7],                         // ADC AL,BH
        &[0x12, 0xf8],                         // ADC BH,AL
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
        &[0x2e, 0x48, 0x13, 0x07],             // Explicit CS override
    ] {
        refuses(instruction);
    }
}

#[test]
fn adc_never_admits_memory_writes_lock_rep_or_other_control_forms() {
    for instruction in [
        &[0x10, 0x07][..],         // ADC [RDI],AL
        &[0x66, 0x11, 0x07],       // ADC [RDI],AX
        &[0x11, 0x07],             // ADC [RDI],EAX
        &[0x48, 0x11, 0x07],       // ADC [RDI],RAX
        &[0x80, 0x17, 1],          // ADC byte [RDI],1
        &[0x48, 0x83, 0x17, 1],    // ADC qword [RDI],1
        &[0xf0, 0x48, 0x11, 0x07], // LOCK RMW
        &[0xf0, 0x48, 0x13, 0xc1], // LOCK register (invalid)
        &[0xf2, 0x48, 0x13, 0xc1],
        &[0xf3, 0x48, 0x13, 0xc1],
        &[0x66, 0x0f, 0x38, 0xf6, 0xc1],    // ADCX is not ADC
        &[0xf3, 0x0f, 0x38, 0xf6, 0xc1],    // ADOX is not ADC
        &[0x48, 0x83, 0xd0, 0, 0xff, 0xd0], // CALL after ADC
        &[0x48, 0x83, 0xd0, 0, 0x0f, 0x05], // SYSCALL after ADC
        &[0x48, 0x83, 0xd0, 0, 0xc2, 8, 0], // Nonordinary RET
    ] {
        refuses(instruction);
    }
}

#[test]
fn adc_does_not_turn_truncation_dead_code_or_bad_edges_into_coverage() {
    for bytes in [
        &[0x48, 0x83, 0xd0][..],                  // Missing immediate
        &[0x48, 0x13],                            // Missing ModRM
        &[0x48, 0x81, 0xd0, 0],                   // Truncated imm32
        &[0x48, 0x83, 0xd0, 0],                   // No RET
        &[0xc3, 0x48, 0x83, 0xd0, 0, 0xc3],       // Unreachable ADC
        &[0xeb, 4, 0x48, 0x83, 0xd0, 0, 0xc3],    // Skipped ADC
        &[0x48, 0x83, 0xd0, 0, 0xeb, 0xfb, 0xc3], // Branch inside ADC
        &[0x48, 0x83, 0xd0, 0, 0xeb, 0x7f, 0xc3], // Outside extent
        &[0x48, 0x83, 0xd0, 0, 0xeb, 0xfa, 0xc3], // No path to RET
    ] {
        assert_eq!(
            admit(bytes, BASE).err(),
            Some(SetupRefusal::EntryExit),
            "{bytes:02x?}"
        );
    }
    for (at, value) in [(26, 0xd4), (36, 0xec), (54, 0x90)] {
        let mut changed = UPPERCASE;
        changed[at] = value;
        assert_eq!(admit(&changed, BASE).err(), Some(SetupRefusal::EntryExit));
    }
    assert_eq!(admit(&UPPERCASE, 0).err(), Some(SetupRefusal::EntryExit));
    assert_eq!(
        admit(&UPPERCASE, u64::MAX - 54).err(),
        Some(SetupRefusal::EntryExit)
    );
    let mut excessive = vec![0x90; 252];
    excessive.extend([0x48, 0x83, 0xd0, 0, 0xc3]);
    assert_eq!(excessive.len(), 257);
    assert_eq!(admit(&excessive, BASE).err(), Some(SetupRefusal::EntryExit));
}

fn w64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn selected_image(stripped: bool) -> Vec<u8> {
    let mut bytes = super::super::tests::fixture();
    bytes[0x1000..0x1029].copy_from_slice(&FIRST_EQUAL);
    bytes[0x1029..0x1030].copy_from_slice(&[0x0f, 0x1f, 0x80, 0, 0, 0, 0]);
    bytes[0x1030..0x1067].copy_from_slice(&UPPERCASE);
    w64(&mut bytes, 0x220, 0x1000); // Existing known FUNC, complete first body.
    w64(&mut bytes, 0x228, 41);
    w64(&mut bytes, 0x3200 + 64 + 16, 0x1000);
    w64(&mut bytes, 0x3200 + 64 + 24, 0x1000);
    w64(&mut bytes, 0x3200 + 64 + 32, 0x67);
    if stripped {
        bytes[0x218..0x230].fill(0);
        bytes[0x280..0x28a].fill(0);
        w64(&mut bytes, 0x3200 + 2 * 64 + 32, 24);
        w64(&mut bytes, 0x3200 + 3 * 64 + 32, 1);
        w64(&mut bytes, 0x2038, 1);
        for (n, value) in [1_u32, 1, 0, 0, 0].into_iter().enumerate() {
            bytes[0x400 + n * 4..0x404 + n * 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    bytes
}

fn two_selections(bytes: &[u8]) {
    for (label, entry, body, returns) in [
        (
            "first-equal",
            0x1000,
            FIRST_EQUAL.as_slice(),
            [0x1022, 0x1028],
        ),
        (
            "uppercase-count",
            0x1030,
            UPPERCASE.as_slice(),
            [0x1058, 0x1066],
        ),
    ] {
        let descriptor = TrustedFunctionSelection::new(bytes, entry, body.len(), label).unwrap();
        let parsed = selection::parse(&descriptor).unwrap();
        assert_eq!(parsed.entry, entry);
        assert_eq!(parsed.code, body);
        assert_eq!(parsed.source, bytes[0x1000..0x2000]);
        assert_eq!(admit(&parsed.code, entry).unwrap().returns(), &returns);
    }
    let first =
        TrustedFunctionSelection::new(bytes, 0x1000, FIRST_EQUAL.len(), "first-equal").unwrap();
    let uppercase =
        TrustedFunctionSelection::new(bytes, 0x1030, UPPERCASE.len(), "uppercase-count").unwrap();
    // Exercise the actual two-selection admission path that runs before dlopen,
    // retaining all the individual-selection assertions above.
    let pair = super::super::normal_module::preflight(&[&first, &uppercase]).unwrap();
    assert_eq!(pair.len(), 2);
    assert_eq!(pair[0].entry, 0x1000);
    assert_eq!(pair[1].entry, 0x1030);
    assert_eq!(pair[0].code, FIRST_EQUAL);
    assert_eq!(pair[1].code, UPPERCASE);
    assert_eq!(pair[0].page, 0x1000);
    assert_eq!(pair[1].page, 0x1000);
    assert_eq!(pair[0].page_offset, 0x1000);
    assert_eq!(pair[1].page_offset, 0x1000);
    assert_eq!(pair[0].source.len(), 4096);
    assert_eq!(pair[0].source, bytes[0x1000..0x2000]);
    assert_eq!(pair[1].source, pair[0].source);
}

#[test]
fn both_complete_selected_bodies_pass_preflight_with_known_function_metadata() {
    two_selections(&selected_image(false));
}

#[test]
fn both_complete_selected_bodies_pass_stripped_preflight_without_symbol_fallback() {
    let bytes = selected_image(true);
    two_selections(&bytes);
    assert_eq!(
        super::super::parse(&bytes, "checksum").err(),
        Some(SetupRefusal::SymbolOwner)
    );
}
