use super::super::{HookContext, SavedExtendedStateLayout, TrampolineImage, TrampolinePlan};
use super::*;
use crate::emission::{ArtifactEmission, SymbolicHook, TargetProfile};
use crate::scanner::InstructionScanner;

const BASE: u64 = 0x400000;
const DEST: u64 = 0x600000;
const NOPS: [[u8; 10]; 2] = [
    [0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0],
    [0x2e, 0x66, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0],
];
unsafe extern "C" fn observer(_: *mut HookContext) {}
fn input() -> ArtifactEmission {
    ArtifactEmission::new(
        TargetProfile::linux_x86_64_legacy_evex(
            SavedExtendedStateLayout::describe_target_fxsave64(),
            1,
        )
        .unwrap(),
        SymbolicHook {
            identity: 1,
            address: Some(BASE + 0x1000),
        },
        vec![],
    )
}
fn body(image: &TrampolineImage, original: u64) -> u64 {
    image
        .instruction_boundaries()
        .iter()
        .find(|(pc, _)| *pc == original)
        .unwrap()
        .1
}
fn exact(image: &TrampolineImage, original: u64, raw: &[u8]) {
    let start = body(image, original);
    let offset = usize::try_from(start - image.address()).unwrap();
    assert_eq!(&image.bytes()[offset..offset + raw.len()], raw);
    for pc in start..start + raw.len() as u64 {
        let mapping = image
            .program_counter_mappings()
            .iter()
            .find(|m| m.generated_start() <= pc && pc < m.generated_end())
            .unwrap();
        assert_eq!(mapping.logical_address(), original);
    }
}

#[test]
fn both_prefix_orders_survive_scalar_ordered_and_artifact_emission() {
    for raw in NOPS {
        let mut code = raw.to_vec();
        code.push(0xc3);
        let scan = InstructionScanner::default().scan(&code, BASE).unwrap();
        assert_eq!(
            scan.instructions()
                .iter()
                .map(|i| i.offset())
                .collect::<Vec<_>>(),
            vec![0, 10]
        );
        let scalar = TrampolinePlan::from_scan(&scan, BASE, observer).unwrap();
        exact(&scalar.emit_at(DEST).unwrap(), BASE, &raw);
        let ordered =
            TrampolinePlan::from_actions(&scan, BASE, BASE + 10, &[(BASE, observer, false)])
                .unwrap();
        exact(&ordered.emit_at(DEST).unwrap(), BASE, &raw);
        let symbolic =
            TrampolinePlan::from_symbolic_window(&scan, BASE, BASE, BASE + 10, false).unwrap();
        let artifact = symbolic.emit_artifact_at(DEST, &input()).unwrap();
        exact(&artifact, BASE, &raw);
        assert!(
            !artifact
                .artifact_metadata()
                .unwrap()
                .qualification_complete()
        );
        assert!(
            artifact
                .artifact_metadata()
                .unwrap()
                .fields()
                .iter()
                .all(|field| !field.role.starts_with("Original"))
        );
        let plain = TrampolinePlan::from_instruction(&scan, BASE).unwrap();
        exact(&plain.emit_artifact_at(DEST, &input()).unwrap(), BASE, &raw);
    }
}

#[test]
fn retained_nop_remains_an_exact_internal_branch_destination() {
    for raw in NOPS {
        let mut code = vec![0xeb, 0]; // Forward JMP to the NOP head.
        code.extend_from_slice(&raw);
        code.extend_from_slice(&[0xeb, 0xf4]); // Backward JMP to the same head.
        let scan = InstructionScanner::default().scan(&code, BASE).unwrap();
        let plan =
            TrampolinePlan::from_symbolic_window(&scan, BASE, BASE, BASE + 14, false).unwrap();
        let image = plan.emit_artifact_at(DEST, &input()).unwrap();
        exact(&image, BASE + 2, &raw);
        let route = image
            .entry_routes()
            .iter()
            .find(|(pc, _)| *pc == BASE + 2)
            .unwrap()
            .1;
        assert_eq!(route, body(&image, BASE + 2));
        for pc in [BASE, BASE + 12] {
            let emitted = body(&image, pc);
            let offset = (emitted - DEST) as usize;
            let instruction = iced_x86::Decoder::with_ip(
                64,
                &image.bytes()[offset..],
                emitted,
                iced_x86::DecoderOptions::NONE,
            )
            .decode();
            assert_eq!(instruction.near_branch_target(), route);
        }
        assert_eq!(
            image
                .artifact_metadata()
                .unwrap()
                .fields()
                .iter()
                .filter(|field| field.role.starts_with("OriginalBranch"))
                .count(),
            2
        );
    }
}

#[test]
fn missing_wrong_truncated_or_changed_nop_bytes_and_offsets_refuse() {
    let scan = InstructionScanner::default().scan(&NOPS[0], BASE).unwrap();
    let original = *scan.instructions()[0].instruction();
    let retained = capture(&scan, &[original]).unwrap();
    assert_eq!(retained, vec![Some(NOPS[0].to_vec())]);
    assert!(instruction(&original, None).is_err());
    assert!(instruction(&original, Some(&[0x90])).is_err());
    assert!(instruction(&original, Some(&NOPS[0][..9])).is_err());
    let mut extended = NOPS[0].to_vec();
    extended.push(0x90);
    assert!(instruction(&original, Some(&extended)).is_err());
    let mut changed = NOPS[0];
    changed[9] = 1;
    assert!(instruction(&original, Some(&changed)).is_err());
    let directive = instruction(&original, retained[0].as_deref()).unwrap();
    let mut block = super::super::encode_relocated_block(&[directive], DEST, None)
        .unwrap()
        .encoded;
    verify(&block, 0, &NOPS[0]).unwrap();
    block.code_buffer[0] ^= 1;
    assert!(verify(&block, 0, &NOPS[0]).is_err());
    block.code_buffer[0] ^= 1;
    block.new_instruction_offsets[0] = u32::MAX;
    assert!(verify(&block, 0, &NOPS[0]).is_err());
    block.new_instruction_offsets[0] = 0;
    block.code_buffer.pop();
    assert!(verify(&block, 0, &NOPS[0]).is_err());
    assert!(verify(&block, 1, &NOPS[0]).is_err());
}

#[test]
fn address_bearing_nops_and_other_instructions_keep_the_existing_encoder_path() {
    for raw in [
        &[0x0f, 0x1f, 0x05, 0, 0, 0, 0][..],   // RIP NOP
        &[0x0f, 0x1f, 0x04, 0x25, 0, 0, 0, 0], // absolute NOP
        &[0x0f, 0x1f, 0x04, 0x05, 0, 0, 0, 0], // index-only NOP
        &[0x48, 0x8b, 0x07],                   // real memory load
        &[0xeb, 0],                            // direct branch
    ] {
        let scan = InstructionScanner::default().scan(raw, BASE).unwrap();
        let original = *scan.instructions()[0].instruction();
        assert_eq!(capture(&scan, &[original]).unwrap(), vec![None]);
        assert_eq!(instruction(&original, None).unwrap(), original);
        assert!(instruction(&original, Some(raw)).is_err());
    }
}

#[test]
fn repeated_semantic_nops_retain_their_own_address_length_and_prefix_bytes() {
    let mut longer = vec![0x66];
    longer.extend_from_slice(&NOPS[0]);
    let raws = [NOPS[0].to_vec(), NOPS[1].to_vec(), longer];
    let code = raws.concat();
    let scan = InstructionScanner::default().scan(&code, BASE).unwrap();
    let originals: Vec<_> = scan
        .instructions()
        .iter()
        .map(|i| *i.instruction())
        .collect();
    // iced equality deliberately ignores IP and length. Source lookup must not.
    assert_eq!(originals[0], originals[1]);
    assert_eq!(originals[0], originals[2]);
    assert_eq!(
        capture(&scan, &originals).unwrap(),
        raws.iter().cloned().map(Some).collect::<Vec<_>>()
    );
    let mut wrong_ip = originals[0];
    wrong_ip.set_ip(BASE + 1);
    assert!(capture(&scan, &[wrong_ip]).is_err());
    let mut wrong_len = originals[0];
    wrong_len.set_len(9);
    wrong_len.set_ip(BASE);
    assert!(capture(&scan, &[wrong_len]).is_err());
    assert!(instruction(&wrong_len, Some(&NOPS[0])).is_err());
    assert!(instruction(&originals[0], Some(&raws[2])).is_err());
    let end = BASE + code.len() as u64;
    let scalar = TrampolinePlan::from_window(&scan, BASE, BASE, end, observer, false).unwrap();
    let live = scalar.emit_at(DEST).unwrap();
    let symbolic = TrampolinePlan::from_symbolic_window(&scan, BASE, BASE, end, false).unwrap();
    let artifact = symbolic.emit_artifact_at(DEST, &input()).unwrap();
    for image in [&live, &artifact] {
        for (offset, raw) in [0, 10, 20].into_iter().zip(&raws) {
            exact(image, BASE + offset, raw);
            assert_eq!(body(image, BASE + offset) - body(image, BASE), offset);
        }
    }
}
