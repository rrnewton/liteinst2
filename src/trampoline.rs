//! Trampoline planning and code generation.
//!
//! Trampolines will be emitted from a single checked plan. Keeping sizing and
//! emission on the same representation prevents the under-allocation bug in
//! the original implementation.

/// Checked byte lengths for the sections of one trampoline.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrampolineLayout {
    /// Context-save and instrumentation-call bytes.
    pub instrumentation_len: usize,
    /// Relocated application instruction bytes.
    pub relocated_len: usize,
    /// Context-restore bytes.
    pub restore_len: usize,
    /// Control-transfer bytes returning to application code.
    pub return_len: usize,
}

impl TrampolineLayout {
    /// Returns the total allocation size, or `None` if the sum overflows.
    pub fn total_len(self) -> Option<usize> {
        self.instrumentation_len
            .checked_add(self.relocated_len)?
            .checked_add(self.restore_len)?
            .checked_add(self.return_len)
    }
}

#[cfg(test)]
mod tests {
    use super::TrampolineLayout;

    #[test]
    fn total_length_includes_every_section() {
        let layout = TrampolineLayout {
            instrumentation_len: 32,
            relocated_len: 12,
            restore_len: 16,
            return_len: 5,
        };
        assert_eq!(layout.total_len(), Some(65));
    }

    #[test]
    fn total_length_rejects_overflow() {
        let layout = TrampolineLayout {
            instrumentation_len: usize::MAX,
            relocated_len: 1,
            ..TrampolineLayout::default()
        };
        assert_eq!(layout.total_len(), None);
    }
}
