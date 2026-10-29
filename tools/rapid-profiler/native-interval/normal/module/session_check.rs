//! Session-only copied metadata joins; opaque stream equality is checked by child.
use super::*;
use rapid_profiler::frontend::{Action, ActionKind, ControllerStatus, HistoryBinding};
use rapid_profiler::frontend_native::HistoryFormat;
use rapid_profiler::generation::GenerationId;
use std::ops::Range;
#[derive(Clone)]
pub(crate) struct Stream {
    pub pid: u32,
    pub install: u64,
    pub identity: CodeIdentity,
    pub functions: [FunctionId; 2],
    pub entries: [u64; 2],
    pub format: HistoryFormat,
}
pub(crate) fn stream(ready: &Ready, pid: u32, s: &Stream) {
    assert!(ready.case.is_session());
    assert_eq!(
        ready.case,
        Case::new_session(
            ready.case.csv.id() - 1,
            ready.case.k,
            ready.case.extents[0],
            ready.case.extents[1],
            ready.case.order[0]
        )
    );
    assert_ne!(pid, 0);
    let entries = ready.functions.each_ref().map(|f| f.entry);
    assert_eq!(
        (
            s.pid,
            s.install,
            s.identity,
            s.functions,
            s.entries,
            s.format
        ),
        (
            pid,
            INSTALL,
            identity(entries[0]),
            FUNCTIONS,
            entries,
            HistoryFormat::AbsoluteV1
        )
    );
}
pub(crate) fn watermark(ready: &Ready, high_water: Option<u64>) {
    assert!(ready.case.is_session());
    assert_eq!(ready.case.admitted(), 4);
    assert_eq!(high_water, Some(1));
}
#[derive(Clone)]
pub(crate) struct Chunk {
    pub number: u64,
    pub range: Range<u64>,
    pub before: HistoryBinding,
    pub after: HistoryBinding,
    pub actions: Vec<Action>,
}
pub(crate) fn chunk(generation: GenerationId, published: bool, c: &Chunk) {
    let bound = HistoryBinding::Published {
        action_index: 0,
        generation,
    };
    let removed = HistoryBinding::Removed {
        action_index: 1,
        generation,
    };
    let (number, range, before, after, kind, current) = if published {
        (
            1,
            0..1,
            HistoryBinding::Initial,
            bound,
            ActionKind::Published,
            Some(generation),
        )
    } else {
        (2, 1..2, bound, removed, ActionKind::Removed, None)
    };
    assert_eq!(
        (c.number, &c.range, c.before, c.after),
        (number, &range, before, after)
    );
    assert_eq!(
        c.actions,
        [Action {
            kind,
            generation,
            function: None,
            current,
            group: None
        }]
    );
}
#[derive(Clone)]
pub(crate) struct Window {
    pub number: u64,
    pub range: Range<u64>,
    pub before: HistoryBinding,
    pub after: HistoryBinding,
    pub actions: Vec<Action>,
    pub status: ControllerStatus,
    pub current: Option<GenerationId>,
    pub enabled: Vec<bool>,
    pub failed: Option<GenerationId>,
}
pub(crate) fn closed(removed: HistoryBinding, w: &Window) {
    assert!(matches!(
        removed,
        HistoryBinding::Removed {
            action_index: 1,
            ..
        }
    ));
    assert_eq!(
        (w.number, &w.range, w.before, w.after),
        (2, &(2..2), removed, removed)
    );
    assert!(w.actions.is_empty());
    assert_eq!(
        (w.status, w.current, w.failed),
        (ControllerStatus::Ready, None, None)
    );
    assert_eq!(w.enabled, [true]); // Mandatory group metadata, not a current epoch.
}
pub(crate) fn banks(count: usize, reclaimed: bool) {
    assert_eq!(count, if reclaimed { 3 } else { 2 });
}
#[cfg(test)]
#[path = "session_check_tests.rs"]
mod tests;
