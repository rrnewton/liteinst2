//! Fixed managed source-view allowance, reserved before even no-pair selection.
//! This is not a compiler stack-frame/RSS estimate or a payload allocation.
use super::rows::PairRows;
use super::*;
use crate::linux::remote::dynamic::owner::admission::mapping::maps::{MapEntries, MapParseError};
use std::iter::{Enumerate, Filter, Zip};
use std::mem::size_of;
use std::slice::{Iter, Split};

type IndexedRow<'a> = (usize, MapEntry<'a>);
type RowPredicate<'a> = fn(&IndexedRow<'a>) -> bool;
type FilteredRows<'a> = Filter<Enumerate<MapEntries<'a>>, RowPredicate<'a>>;
type RowLines<'a> = Split<'a, u8, fn(&u8) -> bool>;
type ComparedBytes<'a> = Enumerate<Zip<Iter<'a, u8>, Iter<'a, u8>>>;

impl InitialMapPlan {
    /// Additive fixed allowance for all four bounded source-evidence families.
    /// Each family includes arguments, retained locals and returned values;
    /// summing them deliberately covers nested calls and sequential overlap.
    /// The caller separately charges immutable raw captures, its own witness
    /// records and native authentication scratch. No read authority is created.
    pub(in crate::linux::remote::dynamic::owner) fn temporary_bytes() -> usize {
        // ParsedMaps::parse / MapEntries::next / parse_line / pair / number:
        // full-table cursor, current row and borrowed raw field descriptions.
        let parser = 4 * size_of::<ParsedMaps<'_>>()
            + 4 * size_of::<MapEntries<'_>>()
            + 2 * size_of::<RowLines<'_>>()
            + 8 * size_of::<MapEntry<'_>>()
            + 32 * size_of::<&[u8]>()
            + 8 * size_of::<Option<u64>>()
            + 8 * size_of::<[u8; 4]>()
            + 32 * size_of::<usize>()
            + 16 * size_of::<u64>()
            + size_of::<[u32; 8]>()
            + 8 * size_of::<Result<MapEntry<'_>, MapParseError>>();
        // PairRows includes both private Columns records. The extra complete
        // PairRows slots cover by-value calls, temporary columns and results
        // without exposing or changing the frozen row leaf's private layout.
        let pair = 8 * size_of::<PairRows<'_>>()
            + 8 * size_of::<MapEntry<'_>>()
            + 16 * size_of::<&[u8]>()
            + 32 * size_of::<usize>()
            + 8 * size_of::<[u8; 4]>()
            + 4 * size_of::<Result<PairRows<'_>, LaunchError>>();
        // Public select / require_original / internal select: previous row,
        // optional candidate, exact recomputed plan, neighbours and alias walk.
        let selection = 4 * size_of::<InitialMapPlan>()
            + 4 * size_of::<Option<(usize, usize, PairRows<'_>)>>()
            + 4 * size_of::<Option<IndexedRow<'_>>>()
            + 4 * size_of::<Enumerate<MapEntries<'_>>>()
            + 8 * size_of::<MapEntry<'_>>()
            + 24 * size_of::<usize>()
            + size_of::<[u64; 8]>()
            + 4 * size_of::<(u32, u32, u64)>()
            + 4 * size_of::<Result<Option<InitialMapPlan>, LaunchError>>();
        // verify_transition can retain one projection while verifying another;
        // view revalidates the complete projection before constructing its
        // two-table borrow. FilteredRows accounts the iterator adaptor header;
        // captured island references are additionally charged below. Literal
        // byte comparisons retain only iterators, never another byte payload.
        let projection = 6 * size_of::<InitialMapProjection>()
            + 2 * size_of::<InitialMapView<'_>>()
            + 4 * size_of::<InitialSourceRow<'_>>()
            + 8 * size_of::<ParsedMaps<'_>>()
            + 8 * size_of::<MapEntries<'_>>()
            + 4 * size_of::<Enumerate<MapEntries<'_>>>()
            + 4 * size_of::<FilteredRows<'_>>()
            + 16 * size_of::<MapEntry<'_>>()
            + 8 * size_of::<Range<u64>>()
            + 8 * size_of::<&Range<u64>>()
            + 4 * size_of::<ComparedBytes<'_>>()
            + 32 * size_of::<usize>()
            + 8 * size_of::<bool>()
            + 4 * size_of::<Result<InitialMapProjection, LaunchError>>()
            + 4 * size_of::<Result<InitialMapView<'_>, LaunchError>>();
        parser + pair + selection + projection
    }
}
