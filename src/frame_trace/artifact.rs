//! Expand only authenticated producer fragments after their final PIC link.
//!
//! Decoding below translates fixed, byte-checked LEA/MOV/ADD/PUSH and CALL
//! templates. It never grants frame authority to an arbitrary decoded image.

use super::*;
use crate::artifact_fixups::{
    self as fixups, BiasDomain, ImageId, ImagePlacement, RelativeAddress, Role, Target,
};
use crate::artifact_fragments::{self, Fragment};
use iced_x86::{Code, Decoder, DecoderOptions};

pub(super) struct ArtifactHelper {
    source: Vec<Instruction>,
    template: Vec<u8>,
    offsets: Vec<u32>,
    fragments: Vec<(usize, Fragment)>,
    domain: u64,
    no_relocations: bool,
}

impl ArtifactHelper {
    pub(super) fn new(
        source: &[Instruction],
        encoded: &BlockEncoderResult,
        fragments: &[(usize, Fragment)],
        domain: u64,
    ) -> Self {
        Self {
            source: source.to_vec(),
            template: encoded.code_buffer.clone(),
            offsets: encoded.new_instruction_offsets.clone(),
            fragments: fragments.to_vec(),
            domain,
            no_relocations: encoded.reloc_infos.is_empty(),
        }
    }

    pub(super) fn resolve(
        &self,
        frames: &HelperFrames,
        address: u64,
        bytes: &[u8],
    ) -> Result<HelperImage, FrameTraceRefusal> {
        let bad = FrameTraceRefusal::InvalidProducerAnnotation;
        if !self.no_relocations
            || frames.stage != FrameStage::SaveAndCall
            || frames.profile != ObservationStackProfile::Legacy128
            || frames.call.is_some()
            || self.source.len() != self.offsets.len()
            || self.offsets.first() != Some(&0)
            || self.offsets.contains(&u32::MAX)
            || self.fragments.len() != 2
            || self.fragments[0].0 >= self.fragments[1].0
        {
            return Err(bad);
        }
        let mut fields = Vec::new();
        let mut hook = None;
        for (number, (index, fragment)) in self.fragments.iter().enumerate() {
            let [field] = fragment.fields.as_slice() else {
                return Err(bad);
            };
            let Target::Address(target) = field.target else {
                return Err(bad);
            };
            if target.domain != BiasDomain(self.domain) {
                return Err(bad);
            }
            let expected = match (number, field.role) {
                (0, Role::LogicalPc) => artifact_fragments::logical_pc(field.target),
                (1, Role::HookCall) => {
                    hook = Some(u64::try_from(target.offset).map_err(|_| bad)?);
                    artifact_fragments::hook_call(field.target)
                }
                _ => return Err(bad),
            };
            if *fragment != expected {
                return Err(bad);
            }
            let start = *self.offsets.get(*index).ok_or(bad)? as usize;
            let end = start.checked_add(fragment.bytes.len()).ok_or(bad)?;
            if self.template.get(start..end) != Some(fragment.bytes.as_slice()) {
                return Err(bad);
            }
            fields.push(field.rebased(start as u64).map_err(|_| bad)?);
        }
        // This authenticates all bytes, including every non-field byte. Both
        // fragment targets and RIP anchors use the final coalesced location.
        let linked = fixups::link_bias_invariant(
            ImageId(address),
            &self.template,
            &fields,
            &[ImagePlacement {
                image: ImageId(address),
                address: RelativeAddress {
                    domain: BiasDomain(self.domain),
                    offset: i128::from(address),
                },
                len: self.template.len() as u64,
            }],
        )
        .map_err(|_| bad)?;
        if linked != bytes {
            return Err(FrameTraceRefusal::HelperBytesChanged);
        }

        let mut source = Vec::new();
        let mut offsets = Vec::new();
        let mut boundaries = vec![None; self.source.len() + 1];
        boundaries[0] = Some(0);
        let mut expanded = HelperFrames::with_profile(frames.stage, frames.profile);
        let mut index = 0;
        let mut fragment_number = 0;
        while index < self.source.len() {
            let start = self.offsets[index] as usize;
            if let Some((_, fragment)) = self
                .fragments
                .get(fragment_number)
                .filter(|(at, _)| *at == index)
            {
                let end = start.checked_add(fragment.bytes.len()).ok_or(bad)?;
                // Account for every DeclareByte chunk, including the 21-byte
                // logical-PC fragment split by the assembler into two chunks.
                while index < self.source.len() && (self.offsets[index] as usize) < end {
                    let next = self
                        .offsets
                        .get(index + 1)
                        .map_or(self.template.len(), |value| *value as usize);
                    if self.source[index].code() != Code::DeclareByte
                        || next <= self.offsets[index] as usize
                        || next > end
                        || frames.effects.iter().any(|(at, _)| *at == index + 1)
                    {
                        return Err(bad);
                    }
                    index += 1;
                }
                if self
                    .offsets
                    .get(index)
                    .map_or(self.template.len(), |v| *v as usize)
                    != end
                {
                    return Err(bad);
                }
                let cuts: &[usize] = if fragment_number == 0 {
                    &[0, 7, 17, 20, 21]
                } else {
                    &[0, 5]
                };
                for span in cuts.windows(2) {
                    let at = start.checked_add(span[0]).ok_or(bad)?;
                    let until = start.checked_add(span[1]).ok_or(bad)?;
                    let pc = address.checked_add(at as u64).ok_or(bad)?;
                    let mut decoder = Decoder::with_ip(
                        64,
                        bytes.get(at..until).ok_or(bad)?,
                        pc,
                        DecoderOptions::NONE,
                    );
                    let instruction = decoder.decode();
                    if instruction.is_invalid()
                        || decoder.can_decode()
                        || instruction.len() != until - at
                    {
                        return Err(bad);
                    }
                    offsets.push(u32::try_from(at).map_err(|_| bad)?);
                    source.push(instruction);
                }
                if fragment_number == 0 {
                    expanded.after(source.len(), FrameEffect::MetadataWord);
                } else {
                    expanded.call(source.len(), FrameCallKind::Observer);
                }
                fragment_number += 1;
            } else {
                if self.source[index].code() == Code::DeclareByte {
                    return Err(bad);
                }
                offsets.push(self.offsets[index]);
                source.push(self.source[index]);
                index += 1;
            }
            boundaries[index] = Some(source.len());
        }
        if fragment_number != self.fragments.len() {
            return Err(bad);
        }
        for &(boundary, effect) in &frames.effects {
            let remapped = boundaries.get(boundary).copied().flatten().ok_or(bad)?;
            expanded.after(remapped, effect);
        }
        expanded.effects.sort_by_key(|(boundary, _)| *boundary);
        expanded.validate_reserved_instructions(&source, 128)?;
        expanded.resolve_with_call(
            &source,
            &BlockEncoderResult {
                rip: address,
                code_buffer: bytes.to_vec(),
                reloc_infos: Vec::new(),
                new_instruction_offsets: offsets,
                constant_offsets: Vec::new(),
            },
            hook,
        )
    }
}
