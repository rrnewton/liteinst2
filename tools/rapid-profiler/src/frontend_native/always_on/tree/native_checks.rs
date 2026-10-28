//! Read-only actual-owner observations for fresh-process native controls only.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSnapshot {
    pub totals: TreeTotals,
    pub next: u64,
    pub gate_base: u64,
    pub rows: [Option<TreeRecord>; EVENTS / 2],
    pub len: usize,
    pub last_external: u64,
    pub failure: Option<BridgeError>,
    pub poisoned: bool,
    pub journal: [u64; 512],
    pub registration: u64,
    pub tid: u64,
    pub stack: [u64; 2],
    pub model_depth: usize,
}

pub fn state() -> Option<StateSnapshot> {
    TREE_STATE.with(|cell| cell.borrow().as_ref().map(runtime::State::native_snapshot))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerSnapshot {
    pub state: StateSnapshot,
    pub gate: Result<u64, GateError>,
    pub finished: Option<TreeTotals>,
    pub cursor: [u64; 3],
    pub cursor_totals: TreeTotals,
    pub active: bool,
}

pub fn owner(thread: &TreeThread) -> OwnerSnapshot {
    assert_eq!(thread.thread, std::thread::current().id());
    assert_eq!(thread.tid, tid());
    OwnerSnapshot {
        state: state().expect("actual attached caller"),
        gate: thread.binding.site.gate.idle_checkpoint(),
        finished: thread.finished,
        cursor: [
            thread.cursor.number,
            thread.cursor.sequence,
            thread.cursor.external,
        ],
        cursor_totals: thread.cursor.totals,
        active: thread.active,
    }
}
