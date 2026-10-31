//! Finite artifact-only JRCXZ lowering. No opaque encoder expansion is admitted.
use super::*;

// JRCXZ taken; JMP fallthrough; taken: JMP rel32 original_target.
// The first two edges are local; all three address fields are linked explicitly.
const BYTES: [u8; 9] = [0xe3, 2, 0xeb, 5, 0xe9, 0, 0, 0, 0];

pub(super) fn eligible(original: &Instruction) -> bool {
    original.code() == Code::Jrcxz_rel8_64 && original.len() == 2
}

pub(super) fn instruction(identity: u64) -> Result<Instruction, TrampolineError> {
    let mut directive = Instruction::with_declare_byte(&BYTES).map_err(encoding_error)?;
    directive.set_ip(identity);
    Ok(directive)
}

pub(super) fn append_fields(
    fields: &mut Vec<Fixup>,
    input: &ArtifactEmission,
    address: u64,
    block: &BlockEncoderResult,
    bridges: &[(usize, Instruction)],
    entries: &[(u64, u64)],
) -> Result<(), TrampolineError> {
    for &(index, original) in bridges {
        if !eligible(&original) {
            return Err(artifact_error("unexpected original in JRCXZ bridge"));
        }
        let offset = block
            .new_instruction_offsets
            .get(index)
            .copied()
            .filter(|offset| *offset != u32::MAX)
            .ok_or_else(|| artifact_error("JRCXZ bridge lost its fixed encoder index"))?
            as usize;
        let end = offset
            .checked_add(BYTES.len())
            .ok_or_else(|| artifact_error("JRCXZ bridge extent overflow"))?;
        if block.code_buffer.get(offset..end) != Some(BYTES.as_slice()) {
            return Err(artifact_error("JRCXZ bridge template moved or changed"));
        }
        let offset = offset as u64;
        let local = |by| Target::Image {
            image: ImageId(address),
            offset: offset + by,
        };
        let original_pc = original.ip();
        let branch_target = match entries
            .iter()
            .find(|(pc, _)| *pc == original.near_branch_target())
        {
            Some((_, generated)) => Target::Image {
                image: ImageId(address),
                offset: generated
                    .checked_sub(address)
                    .ok_or_else(|| artifact_error("JRCXZ internal target precedes image"))?,
            },
            None => artifact_target(input, original.near_branch_target()),
        };
        fields.extend([
            Fixup {
                offset: offset + 1,
                encoding: Encoding::PcRelative8 { next: offset + 2 },
                target: local(4),
                role: Role::OriginalBranchBridge { original_pc },
                expected: vec![2],
            },
            Fixup {
                offset: offset + 3,
                encoding: Encoding::PcRelative8 { next: offset + 4 },
                target: local(9),
                role: Role::OriginalBranchBridge { original_pc },
                expected: vec![5],
            },
            Fixup {
                offset: offset + 5,
                encoding: Encoding::PcRelative32 { next: offset + 9 },
                target: branch_target,
                role: Role::OriginalBranch { original_pc },
                expected: vec![0; 4],
            },
        ]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_jrcxz_bridge_rejects_template_index_and_field_corruption() {
        let original = Decoder::with_ip(64, &[0xe3, 4], 0xa954, DecoderOptions::NONE).decode();
        let input = ArtifactEmission::new(
            crate::emission::TargetProfile::linux_x86_64_legacy_evex(
                SavedExtendedStateLayout::describe_target_fxsave64(),
                7,
            )
            .unwrap(),
            crate::emission::SymbolicHook {
                identity: 1,
                address: None,
            },
            vec![],
        );
        let make_block = || {
            BlockEncoder::encode(
                64,
                InstructionBlock::new(&[instruction(1).unwrap()], 0x500000),
                BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
            )
            .unwrap()
        };
        let block = make_block();
        let fields_for = |block: &BlockEncoderResult, index, original| {
            let mut fields = Vec::new();
            append_fields(
                &mut fields,
                &input,
                0x500000,
                block,
                &[(index, original)],
                &[],
            )
            .map(|()| fields)
        };
        let fields = fields_for(&block, 0, original).unwrap();
        let placement = ImagePlacement {
            image: ImageId(0x500000),
            address: RelativeAddress {
                domain: BiasDomain(7),
                offset: 0x500000,
            },
            len: 9,
        };
        let link = |fields: &[Fixup]| {
            fixups::link_bias_invariant(placement.image, &block.code_buffer, fields, &[placement])
        };
        assert!(link(&fields).is_ok());
        // The whole fixed stencil is authenticated, including its opcodes.
        for byte in 0..BYTES.len() {
            let mut changed = make_block();
            changed.code_buffer[byte] ^= 1;
            assert!(fields_for(&changed, 0, original).is_err());
        }
        let mut missing = make_block();
        missing.new_instruction_offsets[0] = u32::MAX;
        assert!(fields_for(&missing, 0, original).is_err());
        assert!(fields_for(&block, 1, original).is_err());
        let other = Decoder::with_ip(64, &[0xe2, 4], 0xa954, DecoderOptions::NONE).decode();
        assert!(fields_for(&block, 0, other).is_err());
        let mut changed = fields.clone();
        changed[2].expected[0] = 1;
        assert!(matches!(
            link(&changed),
            Err(fixups::Error::TemplateMismatch { .. })
        ));
        let mut changed = fields.clone();
        changed[2].target = Target::Address(RelativeAddress {
            domain: BiasDomain(8),
            offset: 0xa95a,
        });
        assert!(matches!(
            link(&changed),
            Err(fixups::Error::CrossBiasDomain { .. })
        ));
        let mut changed = fields.clone();
        changed[2].target = Target::UnresolvedSymbol(1);
        assert!(matches!(
            link(&changed),
            Err(fixups::Error::UnresolvedSymbol(1))
        ));
        let mut changed = fields.clone();
        changed[2].target = Target::Image {
            image: placement.image,
            offset: 10,
        };
        assert!(matches!(
            link(&changed),
            Err(fixups::Error::ImageOffsetOutOfBounds { .. })
        ));
    }
}
