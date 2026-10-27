//! Feature-only immutable provenance of an actual retained kernel attempt.
use super::*;

impl RuntimeOwner {
    pub(in crate::linux::remote::dynamic::owner::admission::runtime) fn consumer_journal_binding(
        &self,
        index: usize,
    ) -> Option<(&RuntimeKernelIdentity, &AdmissionStop)> {
        let attempt = self.kernel_attempts.get(index)?;
        Some((attempt.identity.as_ref()?, &attempt.stop))
    }
}
