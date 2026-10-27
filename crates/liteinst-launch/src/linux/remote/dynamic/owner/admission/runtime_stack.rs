//! Descriptive owned-stack storage and closed validators only. This increment
//! has no held-stop acquisition, executable permit, native completion, or census
//! mutation. Supplying matching records never authenticates a live tracee.
#![forbid(unsafe_code)]
use super::super::bootstrap::{BootstrapMm, Request, StateSlot};
use super::super::trusted::{AdmissionPhase, AdmissionStop, TaskStateSnapshot};
use super::exact_storage::{self, AllocationError};
use super::mapping::maps::{MapEntry, ParsedMaps, parse_header_line};
use crate::linux::RegisterSnapshot;
use std::mem::size_of;
use std::ops::Range;

pub(in crate::linux::remote::dynamic::owner::admission) mod access;
pub(in crate::linux::remote::dynamic::owner::admission) mod metadata;
pub(in crate::linux::remote::dynamic::owner::admission) mod operand;
pub(in crate::linux::remote::dynamic::owner::admission) mod profile;
pub(in crate::linux::remote::dynamic::owner::admission) mod storage;
#[cfg(test)]
mod tests;

pub(in crate::linux::remote::dynamic::owner::admission) const BYTES: usize = 64 * 1024;
pub(in crate::linux::remote::dynamic::owner::admission) const ROWS: usize = 512;
pub(in crate::linux::remote::dynamic::owner::admission) const PAGE: u64 = 4096;
pub(in crate::linux::remote::dynamic::owner::admission) const USER_END: u64 = 1 << 47;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner::admission) enum StackError {
    Capacity,
    Allocation,
    Reused,
    Aborted,
    Incomplete,
    Request,
    Framing,
    Maps,
    Metadata,
    Flags,
    Layout,
    Xstate,
    Mode,
    Provenance,
    Geometry,
    Encoding,
    Pagemap,
    Word,
    State,
}
impl From<AllocationError> for StackError {
    fn from(error: AllocationError) -> Self {
        match error {
            AllocationError::Capacity => Self::Capacity,
            AllocationError::Allocation => Self::Allocation,
        }
    }
}
fn add(a: usize, b: usize) -> Result<usize, StackError> {
    a.checked_add(b).ok_or(StackError::Capacity)
}
fn low(address: u64) -> bool {
    (PAGE..USER_END).contains(&address)
}
fn interval(range: &Range<u64>) -> bool {
    low(range.start) && low(range.end) && range.start < range.end
}
fn overlaps(a: &Range<u64>, b: &Range<u64>) -> bool {
    a.start < b.end && b.start < a.end
}
fn maps(raw: &[u8]) -> Result<ParsedMaps<'_>, StackError> {
    if raw.len() > BYTES {
        return Err(StackError::Capacity);
    }
    ParsedMaps::parse(raw, ROWS).map_err(|_| StackError::Maps)
}
