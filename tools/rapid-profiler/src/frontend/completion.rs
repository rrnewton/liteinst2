//! Same-call proof of the model's original local exit check.
//! No owner, callback, shared observation or mutation can escape the token.
use super::{Completion, ExitError, ModelReturnSlot, Observation, Payload, ThreadModel};

// Field privacy prevents the parent and sibling modules from manufacturing a
// checked count or replacing either exclusively borrowed object. No Clone,
// Copy, Drop, raw constructor, mutable view or extraction API is provided.
pub(super) struct CheckedExit<'a> {
    model: &'a mut ThreadModel,
    slot: &'a mut ModelReturnSlot,
    children: u64,
    next: u64,
}

impl<'a> CheckedExit<'a> {
    #[inline]
    pub(super) fn check(
        model: &'a mut ThreadModel,
        slot: &'a mut ModelReturnSlot,
    ) -> Result<Self, ExitError> {
        let (children, next) = model.exit_check(slot)?;
        Ok(Self {
            model,
            slot,
            children,
            next,
        })
    }

    pub(super) fn children(&self) -> u64 {
        self.children
    }

    // A successful check owns both borrows through the original mutation and
    // hook/unwind tail. An unused token only ends those borrows; it does not pop,
    // restore, cancel, complete, publish, or retain anything.
    pub(super) fn complete(
        self,
        end: Observation,
        before_release: impl FnOnce(),
        before_close: impl FnOnce(),
    ) -> (Completion, Payload) {
        let frame = self.model.frames.pop().expect("checked frame");
        let original = frame.slot.word;
        let result = frame.complete(end, self.children, before_release, before_close);
        self.model.completed_sequence = self.next;
        self.slot.word = original;
        result
    }
}
