//! Descriptive complete-table projection for one original R/RX page pair.
//! Immutable actual captures and the completed native producer remain separate
//! prerequisites. No value here grants a read, release, source or census right.
use super::mapping::maps::{MapEntry, ParsedMaps};
use super::source_identity::fixed_vsyscall;
use crate::LaunchError;
use crate::linux::{EntryEvidence, FirstImage};
use std::ops::Range;

mod inventory;
mod plan;
mod rows;
mod temporary;
#[cfg(test)]
mod tests;

const PAGE: u64 = 4096;
const MAP_BYTES: usize = 64 * 1024;
const MAP_ROWS: usize = 512;
// The existing native input profile's maximum lower user half. Actual held
// mappings, not this descriptive ceiling, prove the platform address width.
const USER_END: u64 = 1 << 56;

fn invalid() -> LaunchError {
    LaunchError::Invalid("initial coalescence complete inventory differs")
}

fn parse(raw: &[u8]) -> Result<ParsedMaps<'_>, LaunchError> {
    if raw.len() > MAP_BYTES {
        return Err(invalid());
    }
    ParsedMaps::parse(raw, MAP_ROWS).map_err(|_| invalid())
}

fn file(row: MapEntry<'_>) -> (u32, u32, u64) {
    (row.device_major, row.device_minor, row.inode)
}

fn executable(row: MapEntry<'_>) -> bool {
    row.permissions.bytes()[2] == b'x' && !fixed_vsyscall(row)
}

fn span(raw: &[u8], row: MapEntry<'_>) -> (usize, usize) {
    // Every caller obtains row from this exact immutable ParsedMaps buffer.
    (
        row.raw_line.as_ptr() as usize - raw.as_ptr() as usize,
        row.raw_line.len(),
    )
}

/// Fixed scalar plan only. The owner keeps its original capture immutable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct InitialMapPlan {
    original_rows: usize,
    original_bytes: usize,
    executable_count: usize,
    lower_index: usize,
    upper_index: usize,
    lower_span: (usize, usize),
    upper_span: (usize, usize),
    target_executable_ordinal: usize,
    pair_start: u64,
    pair_end: u64,
    rx_start: u64,
    lower_offset: u64,
    executable: (u32, u32, u64),
    entry: u64,
}

/// Fixed scalar description of an exhaustively checked capture. This is not
/// the non-Clone completed native bootstrap proof owned by the producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::linux::remote::dynamic::owner) struct InitialMapProjection {
    plan: InitialMapPlan,
    cleared_prefix: usize,
    merged: bool,
    current_rows: usize,
    current_bytes: usize,
    island: (u64, u64),
    island_index: usize,
    island_span: (usize, usize),
    lower_current_index: usize,
    rx_current_index: usize,
    lower_current_span: (usize, usize),
    rx_current_span: (usize, usize),
}

/// A revalidated borrow of both complete raw tables; no copied row inventory.
pub(in crate::linux::remote::dynamic::owner) struct InitialMapView<'a> {
    original: ParsedMaps<'a>,
    current: ParsedMaps<'a>,
    projection: InitialMapProjection,
}

/// Original RX identity is deliberately distinct from its actual container.
pub(in crate::linux::remote::dynamic::owner) struct InitialSourceRow<'a> {
    pub(in crate::linux::remote::dynamic::owner) original: MapEntry<'a>,
    pub(in crate::linux::remote::dynamic::owner) current: MapEntry<'a>,
    pub(in crate::linux::remote::dynamic::owner) original_index: usize,
    pub(in crate::linux::remote::dynamic::owner) current_index: usize,
    pub(in crate::linux::remote::dynamic::owner) original_span: (usize, usize),
    pub(in crate::linux::remote::dynamic::owner) current_span: (usize, usize),
}
