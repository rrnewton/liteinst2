//! Prepaid copies of the three observer prefixes. These do not duplicate or
//! replace the production native owners, or construct a native completion.
use super::*;
use crate::linux::remote::dynamic::owner::admission::census::{
    PreparedCallPrefixMirror, PreparedStackPrefixMirror, call_prefix_mirror_temporary_bytes,
    stack_prefix_mirror_temporary_bytes,
};
use std::mem::size_of;

pub(super) struct PrefixMirrors {
    pub(super) stack: [PreparedStackPrefixMirror; 2],
    pub(super) call: PreparedCallPrefixMirror,
}

fn sum(values: impl IntoIterator<Item = usize>) -> Result<usize, OracleError> {
    values.into_iter().try_fold(0_usize, |total, value| {
        total.checked_add(value).ok_or(OracleError::Invalid(
            "observer prefix mirror accounting overflows",
        ))
    })
}

// ConsumerProgress's mutating/validation methods stay census-private. Read the
// exact admission-visible fields with the same closed completeness predicate.
fn require_progress(
    started: bool,
    complete: bool,
    first_failure: Option<CensusConsumerError>,
) -> Result<(), OracleError> {
    if !started || !complete || first_failure.is_some() {
        return Err(OracleError::Observer(CensusConsumerError::Incomplete));
    }
    Ok(())
}

impl PrefixMirrors {
    pub(super) fn empty() -> Self {
        Self {
            stack: std::array::from_fn(|_| PreparedStackPrefixMirror::empty()),
            call: PreparedCallPrefixMirror::empty(),
        }
    }

    fn padding_bytes() -> Result<usize, OracleError> {
        size_of::<Self>()
            .checked_sub(sum([
                2 * size_of::<PreparedStackPrefixMirror>(),
                size_of::<PreparedCallPrefixMirror>(),
            ])?)
            .ok_or(OracleError::Invalid(
                "observer prefix mirror headers differ",
            ))
    }

    pub(super) fn reservation_bytes(window: usize) -> Result<usize, OracleError> {
        sum([
            Self::padding_bytes()?,
            PreparedStackPrefixMirror::reservation_bytes()?,
            PreparedStackPrefixMirror::reservation_bytes()?,
            PreparedCallPrefixMirror::reservation_bytes(window)?,
        ])
    }

    pub(super) fn allocated_bytes(&self) -> Result<usize, OracleError> {
        sum([
            Self::padding_bytes()?,
            self.stack[0].allocated_bytes()?,
            self.stack[1].allocated_bytes()?,
            self.call.allocated_bytes()?,
        ])
    }

    /// The empty owners are already installed. Only an actual unwind in a
    /// mirror's own allocator poisons that mirror; the exact payload resumes.
    pub(super) fn allocate_payloads(&mut self, window: usize) -> Result<(), OracleError> {
        for mirror in &mut self.stack {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                mirror.allocate_payloads()
            })) {
                Ok(result) => result?,
                Err(payload) => {
                    mirror.mark_aborted();
                    std::panic::resume_unwind(payload);
                }
            }
            let progress = mirror.progress().0;
            require_progress(progress.started, progress.complete, progress.first_failure)?;
        }
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.call.allocate_payloads(window)
        })) {
            Ok(result) => result?,
            Err(payload) => {
                self.call.mark_aborted();
                std::panic::resume_unwind(payload);
            }
        }
        let progress = self.call.progress().0;
        require_progress(progress.started, progress.complete, progress.first_failure)?;
        Ok(())
    }

    /// Used only after the three independently recorded cleanup comparisons.
    /// Incomplete source observations may be copied, but incomplete mirrors
    /// themselves can never support preservation or a successful result.
    pub(super) fn require_complete(&self) -> Result<(), OracleError> {
        for mirror in &self.stack {
            let (allocation, capture) = mirror.progress();
            require_progress(
                allocation.started,
                allocation.complete,
                allocation.first_failure,
            )?;
            require_progress(capture.started, capture.complete, capture.first_failure)?;
        }
        let (allocation, capture) = self.call.progress();
        require_progress(
            allocation.started,
            allocation.complete,
            allocation.first_failure,
        )?;
        require_progress(capture.started, capture.complete, capture.first_failure)?;
        Ok(())
    }

    pub(super) fn temporary_bytes() -> Result<usize, OracleError> {
        sum([
            stack_prefix_mirror_temporary_bytes()?,
            stack_prefix_mirror_temporary_bytes()?,
            call_prefix_mirror_temporary_bytes()?,
            size_of::<Self>(),
            size_of::<[PreparedStackPrefixMirror; 2]>(),
            4 * size_of::<Result<(), CensusConsumerError>>(),
            4 * size_of::<Result<Result<(), CensusConsumerError>, custody::Unwind>>(),
            4 * size_of::<Result<(), OracleError>>(),
            // Four returned pairs of references to concrete sized progress values.
            8 * size_of::<&'static usize>(),
            8 * size_of::<usize>(),
            8 * size_of::<&'static PreparedStackPrefixMirror>(),
            2 * size_of::<std::slice::Iter<'static, PreparedStackPrefixMirror>>(),
            2 * size_of::<std::slice::IterMut<'static, PreparedStackPrefixMirror>>(),
            size_of::<[usize; 14]>() + size_of::<std::array::IntoIter<usize, 14>>(),
            4 * size_of::<[bool; 2]>(),
            4 * size_of::<Option<CensusConsumerError>>(),
            2 * size_of::<Result<(), OracleError>>(),
            size_of::<[usize; 18]>() + size_of::<std::array::IntoIter<usize, 18>>(),
        ])
    }
}
