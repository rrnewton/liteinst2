//! Explicit grouped suffix encoding. All singleton paths retain their old policy.
use super::*;

pub const GROUPED_PHYSICAL_MIN5_ALPHABET_SUFFIX60_UPSTREAM_PROFILE: &str =
    "jumps-gpr-stack64-block-physical-min5-alphabet-suffix60-upstream-v1";

/// Physical minimum windows with one-byte 0x60 at routed suffix heads only.
/// Neither this profile nor the artifact grants native or runtime qualification.
pub fn prepare_disassembly_jump_stack_grouped_physical_min5_alphabet_suffix60_upstream_fixed_exec(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
) -> Result<Product, Error> {
    prepare_grouped(
        original,
        selected,
        GroupProfile::PhysicalMin5AlphabetSuffix60Upstream,
    )
}

pub fn prepare_disassembly_jump_stack_grouped_physical_min5_alphabet_suffix60_upstream_with_ledger_storage(
    original: &[u8],
    selected: &disassembly::whole::JumpStackWholeSelection,
    storage: LedgerStorage,
) -> Result<Product, Error> {
    prepare_grouped_with_storage(
        original,
        selected,
        GroupProfile::PhysicalMin5AlphabetSuffix60Upstream,
        storage,
    )
}

pub fn grouped_physical_min5_alphabet_suffix60_upstream_fixed_exec_metadata() -> String {
    grouped_metadata(GroupProfile::PhysicalMin5AlphabetSuffix60Upstream)
}

pub fn grouped_physical_min5_alphabet_suffix60_upstream_fixed_exec_binding_policy(
    binding: FixedImageBinding,
    selection: ContentId,
    grouping: ContentId,
) -> Vec<u8> {
    GroupProfile::PhysicalMin5AlphabetSuffix60Upstream.binding_policy(binding, selection, grouping)
}

#[cfg(test)]
mod tests;
