//! Conservative sizing of the exact prepared artifact IR, never a trial image.
use super::*;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) struct OrderedPreparation {
    pub(super) extended_state: SavedExtendedStateLayout,
    pub(super) fragments: Vec<(usize, InstrumentationEmission)>,
    pub(super) original_operands: Vec<(usize, Instruction)>,
    pub(super) jrcxz_bridges: Vec<(usize, Instruction)>,
    pub(super) emitted_nops: Vec<(usize, Vec<u8>)>,
    pub(super) encoded_instructions: Vec<Instruction>,
    pub(super) heads: Vec<(u64, usize, usize, bool)>,
    pub(super) first_hook_lengths: Option<(usize, usize, usize)>,
    pub(super) helper_frames: Vec<(usize, u64, usize, usize, HelperFrames, HelperFrames)>,
    pub(super) clock_specs: Vec<(u64, usize, usize, backedge_clock::GateSpec)>,
    pub(super) precontext_specs: Vec<(usize, usize, usize, precontext::GateSpec)>,
    pub(super) early_control_specs: Vec<(usize, usize, usize, early_control::GateSpec)>,
}

/// Opaque owned source/fragment preparation. Consuming it permits one actual
/// encode at the chosen address. A size certificate is not a reachability,
/// field-ledger, ownership, loader or runtime qualification certificate.
pub(crate) struct PreparedArtifact {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    plan: TrampolinePlan,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    input: ArtifactEmission,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    preparation: OrderedPreparation,
    size_bound: usize,
}

impl PreparedArtifact {
    pub(crate) fn new(
        plan: &TrampolinePlan,
        input: &ArtifactEmission,
    ) -> Result<Self, TrampolineError> {
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = (plan, input);
            Err(TrampolineError::UnsupportedPlatform)
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            // Same supported artifact constructors as ordinary artifact emission.
            if plan.ptrace_stops
                || plan.clock.is_some()
                || !plan.controls.is_empty()
                || !matches!(
                    plan.kind,
                    TrampolineKind::PatchWindow | TrampolineKind::Instruction
                )
            {
                return Err(artifact_error(
                    "artifact profile does not implement ptrace, controlled or multi-action binding",
                ));
            }
            let preparation = plan.prepare_ordered(Some(input), false, false)?;
            Self::from_preparation(plan, input, preparation)
        }
    }

    // This constructor cannot accept an arbitrary live plan/PC pair.
    pub(super) fn for_observation_window(
        window: &ArtifactObservationWindow,
        input: &ArtifactEmission,
    ) -> Result<Self, TrampolineError> {
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = (window, input);
            Err(TrampolineError::UnsupportedPlatform)
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let preparation = window.prepare(input)?;
            Self::from_preparation(window.plan(), input, preparation)
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn from_preparation(
        plan: &TrampolinePlan,
        input: &ArtifactEmission,
        preparation: OrderedPreparation,
    ) -> Result<Self, TrampolineError> {
        let size_bound = prepared_bound(&preparation)?;
        Ok(Self {
            plan: plan.clone(),
            input: input.clone(),
            preparation,
            size_bound,
        })
    }

    pub(crate) const fn size_bound(&self) -> usize {
        self.size_bound
    }

    pub(crate) fn emit_at(self, address: u64) -> Result<TrampolineImage, TrampolineError> {
        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = address;
            Err(TrampolineError::UnsupportedPlatform)
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            self.plan.emit_prepared_ordered_at(
                address,
                Some(&self.input),
                None,
                self.preparation,
                Some(self.size_bound),
            )
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn prepared_bound(preparation: &OrderedPreparation) -> Result<usize, TrampolineError> {
    if !preparation.clock_specs.is_empty()
        || !preparation.precontext_specs.is_empty()
        || !preparation.early_control_specs.is_empty()
        || !preparation.helper_frames.is_empty()
    {
        return Err(artifact_error("unaccounted prepared artifact extension"));
    }
    // The artifact continuation is always the existing fixed five-byte E9.
    let mut bound = NEAR_RETURN_JUMP_BYTES;
    for (index, instruction) in preparation.encoded_instructions.iter().enumerate() {
        let bytes = match instruction.code() {
            Code::Zero_bytes => 0,
            // Helpers, retained source NOPs and the fixed JRCXZ bridge are
            // already exact contiguous byte directives in this very IR.
            Code::DeclareByte => instruction.declare_data_len(),
            Code::DeclareWord | Code::DeclareDword | Code::DeclareQword | Code::INVALID => {
                return Err(artifact_error("unsupported prepared artifact directive"));
            }
            _ if preparation
                .original_operands
                .iter()
                .any(|(at, _)| *at == index) =>
            {
                15
            }
            _ => return Err(artifact_error("unaccounted prepared artifact instruction")),
        };
        if instruction.code() == Code::DeclareByte && !(1..=16).contains(&bytes) {
            return Err(artifact_error("invalid prepared artifact byte directive"));
        }
        bound = bound
            .checked_add(bytes)
            .ok_or_else(|| artifact_error("prepared artifact size bound overflow"))?;
    }
    Ok(bound)
}

// An accepted fitting image has no hidden encoder padding, pointer table,
// synthesized multi-instruction expansion or relay. The ordinary artifact
// field ledger still independently proves every original address operand.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn verify_block(
    instructions: &[Instruction],
    block: &RelocatedBlock,
    address: u64,
    bound: usize,
) -> Result<(), TrampolineError> {
    let encoded = &block.encoded;
    if block.terminal_jump_offset.is_some()
        || !block.branch_relays.is_empty()
        || !encoded.reloc_infos.is_empty()
        || encoded.new_instruction_offsets.len() != instructions.len()
    {
        return Err(artifact_error(
            "unaccounted fitting artifact encoder extension",
        ));
    }
    let mut cursor = 0_usize;
    for (instruction, &offset) in instructions.iter().zip(&encoded.new_instruction_offsets) {
        if offset == u32::MAX || offset as usize != cursor {
            return Err(artifact_error(
                "fitting artifact encoder lost contiguous ownership",
            ));
        }
        let len = match instruction.code() {
            Code::Zero_bytes => 0,
            Code::DeclareByte => {
                let len = instruction.declare_data_len();
                if !(1..=16).contains(&len)
                    || (0..len).any(|i| {
                        encoded.code_buffer.get(cursor + i).copied()
                            != Some(instruction.get_declare_byte_value(i))
                    })
                {
                    return Err(artifact_error("fitting artifact fixed bytes changed"));
                }
                len
            }
            _ => {
                let ip = address
                    .checked_add(cursor as u64)
                    .ok_or(TrampolineError::AddressNotRepresentable { address })?;
                let bytes = encoded
                    .code_buffer
                    .get(cursor..)
                    .ok_or_else(|| artifact_error("fitting artifact instruction outside image"))?;
                let decoded = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE).decode();
                if decoded.is_invalid() || !(1..=15).contains(&decoded.len()) {
                    return Err(artifact_error(
                        "fitting artifact ordinary instruction is unaccounted",
                    ));
                }
                decoded.len()
            }
        };
        cursor = cursor
            .checked_add(len)
            .ok_or_else(|| artifact_error("fitting artifact encoded extent overflow"))?;
    }
    if cursor != encoded.code_buffer.len()
        || cursor
            .checked_add(NEAR_RETURN_JUMP_BYTES)
            .is_none_or(|len| len > bound)
    {
        return Err(artifact_error(
            "fitting artifact encoded bytes exceed certificate",
        ));
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests;
