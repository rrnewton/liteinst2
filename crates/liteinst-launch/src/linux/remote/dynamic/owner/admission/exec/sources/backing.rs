//! Compatibility namespace for the unchanged exec backing controls.
pub(super) use super::super::super::source_identity::backing::{
    DescriptorIdentity, ExecutableIdentity, temporary_bytes,
};
#[cfg(test)]
use super::super::super::source_identity::backing::{descriptor_value, projection};
use super::*;
#[cfg(test)]
mod tests;

pub(super) fn observe(
    read: &HeldSourceRead<'_>,
    storage: &mut [u8],
) -> Result<ExecutableIdentity, GateError> {
    read.executable_projection(storage)
}
#[cfg(any(test, feature = "dev-exec-backing-cleanup"))]
pub(super) fn cleanup_leaf(owner: &Owner, path: &std::path::Path, until: Instant) {
    super::super::super::source_identity::backing::cleanup_leaf(owner, path, until);
}
