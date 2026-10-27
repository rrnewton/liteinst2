//! Explicit detached diagnostic copies for existing model/exec controls only.
//! No Clone exists without this test/dev cfg; preparation is never Clone.
use super::*;
impl OrdinaryHistoryPayloads {
    pub(super) fn try_clone_with(
        &self,
        mut before: impl FnMut(usize) -> Result<(), SharedError>,
    ) -> Result<Self, SharedError> {
        let mut copy = Self::empty(self.binding, self.owner);
        copy.trace = self.trace;
        copy.headers = self.headers.clone();
        copy.prior = self.prior;
        copy.native = self.native;
        for (index, source) in self.payloads.iter().enumerate() {
            before(index)?;
            let mut bytes =
                exact_storage::empty_bytes(source.bytes.capacity()).map_err(allocation_error)?;
            bytes.extend_from_slice(&source.bytes);
            copy.payloads[index] = Payload {
                bytes,
                copy: source.copy,
            };
        }
        Ok(copy)
    }
}
impl Clone for OrdinaryHistoryPayloads {
    fn clone(&self) -> Self {
        // Clone cannot return an allocation error. Fail the diagnostic caller;
        // never return a truncated/fake successful copy or mutate the original.
        self.try_clone_with(|_| Ok(()))
            .expect("ordinary archive diagnostic clone allocation failed")
    }
}
