//! One continuous demand cache from root entry: 64-byte lines, four sets,
//! two ways, true LRU, write allocate and write back. Full virtual addresses.
//! No prefetch, speculation, instruction fetch, translation or hardware claim.
//! The fixed tree only dirties its CALL line and never evicts that line.
use super::truth::{CHILD_NODE, Case, EVENTS, Event, EventKind, INPUT_BYTES, ROOT_NODE};

const LINE: u64 = 64;
const SETS: usize = 4;
const WAYS: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Address,
    Trace,
    Policy,
    Count,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Summary {
    pub accesses: usize,
    pub hits: usize,
    pub misses: usize,
    pub root_misses: usize,
    pub child_misses: usize,
    pub writebacks: usize,
    pub hit_by_event: Vec<bool>,
}
#[derive(Clone, Copy)]
struct Resident {
    line: u64,
    dirty: bool,
}

// Each set holds MRU then LRU. A hit moves the whole line, including its dirty
// bit; a store hit also marks it dirty. A dirty eviction is not a demand access.
fn demand(events: &[Event]) -> (Vec<bool>, usize) {
    let mut sets: [[Option<Resident>; WAYS]; SETS] = [[None; WAYS]; SETS];
    let mut bits = Vec::with_capacity(events.len());
    let mut writebacks = 0;
    for event in events {
        let line = event.address / LINE;
        let set = &mut sets[(line % SETS as u64) as usize];
        let found = set.iter().position(|r| r.is_some_and(|r| r.line == line));
        bits.push(found.is_some());
        let mut resident = if let Some(index) = found {
            set[index].expect("found resident")
        } else {
            writebacks += usize::from(set[1].is_some_and(|r| r.dirty));
            Resident { line, dirty: false }
        };
        resident.dirty |= event.kind == EventKind::CallStore;
        if found != Some(0) {
            set[1] = set[0];
        }
        set[0] = Some(resident);
    }
    (bits, writebacks)
}
// Independent formulation: the distinct same-set lines between two uses,
// without mutable ways, ages or replacement state. Writes allocate too.
fn reuse_distance(events: &[Event]) -> Vec<bool> {
    let lines: Vec<_> = events.iter().map(|e| e.address / LINE).collect();
    lines
        .iter()
        .enumerate()
        .map(|(i, &line)| {
            let Some(previous) = lines[..i].iter().rposition(|&p| p == line) else {
                return false;
            };
            let competitors: std::collections::BTreeSet<_> = lines[previous + 1..i]
                .iter()
                .copied()
                .filter(|p| p % SETS as u64 == line % SETS as u64)
                .collect();
            competitors.len() < WAYS
        })
        .collect()
}
fn operand(e: &Event, node: u8, kind: EventKind, address: u64) -> bool {
    e.node == node && e.kind == kind && e.address == address && e.width == 8
}
fn literal_bits(case: Case) -> Vec<bool> {
    let mut bits = vec![true; EVENTS];
    bits[0] = false; // CALL allocates the stack line, before either RET.
    bits[1] = false; // Count first touches input node0.
    match case {
        Case::Fit2 => bits[4] = false, // First payload in node4.
        Case::Conflict3 => {
            for i in 1..64 {
                bits[2 + 2 * i] = false;
            }
        }
    }
    bits
}

/// Require the complete ordered, function-tagged trace and fixed geometry.
/// The native oracle must first authenticate every value/address against actual
/// original instructions and independent truth. This model cannot prove that
/// a CALL or RET executed, or authenticate code addresses and payload values.
pub fn check(case: Case, data: u64, root_rsp: u64, events: &[Event]) -> Result<Summary, Error> {
    let data_end = data.checked_add(INPUT_BYTES as u64).ok_or(Error::Address)?;
    let child_rsp = root_rsp.checked_sub(16).ok_or(Error::Address)?;
    let stack_end = root_rsp.checked_add(8).ok_or(Error::Address)?;
    let stack_line = child_rsp / LINE;
    if data % LINE != 0
        || data / LINE % SETS as u64 != 2
        || root_rsp % 16 != 8
        || stack_line != (stack_end - 1) / LINE
        || stack_line % SETS as u64 != 3
        || !(data_end <= child_rsp || stack_end <= data)
    {
        return Err(Error::Address);
    }
    if events.len() != EVENTS {
        return Err(Error::Trace);
    }
    for e in events {
        let end = e
            .address
            .checked_add(u64::from(e.width))
            .ok_or(Error::Address)?;
        if e.width != 8 || e.address % 8 != 0 || e.address / LINE != (end - 1) / LINE {
            return Err(Error::Address);
        }
    }
    if !operand(&events[0], ROOT_NODE, EventKind::CallStore, child_rsp)
        || !operand(&events[1], CHILD_NODE, EventKind::Count, data + 16)
        || events[1].value != 64
        || !operand(&events[130], CHILD_NODE, EventKind::ChildReturn, child_rsp)
        || events[130].value != events[0].value
        || !operand(&events[131], ROOT_NODE, EventKind::RootReturn, root_rsp)
    {
        return Err(Error::Trace);
    }
    let cycle = case.cycle();
    for i in 0..64 {
        let node = cycle[i % cycle.len()];
        let next = cycle[(i + 1) % cycle.len()];
        if !operand(
            &events[2 + 2 * i],
            CHILD_NODE,
            EventKind::Payload,
            data + (node * 64 + 8) as u64,
        ) || !operand(
            &events[3 + 2 * i],
            CHILD_NODE,
            EventKind::Link,
            data + (node * 64) as u64,
        ) || events[3 + 2 * i].value != (next * 64) as u64
        {
            return Err(Error::Trace);
        }
    }
    let (hit_by_event, writebacks) = demand(events);
    if hit_by_event != reuse_distance(events) || hit_by_event != literal_bits(case) {
        return Err(Error::Policy);
    }
    let hits = hit_by_event.iter().filter(|&&h| h).count();
    let misses = EVENTS - hits;
    let root_misses = events
        .iter()
        .zip(&hit_by_event)
        .filter(|(e, h)| e.node == ROOT_NODE && !**h)
        .count();
    let child_misses = events
        .iter()
        .zip(&hit_by_event)
        .filter(|(e, h)| e.node == CHILD_NODE && !**h)
        .count();
    let expected = match case {
        Case::Fit2 => 3,
        Case::Conflict3 => 65,
    };
    if misses != expected || root_misses != 1 || child_misses != expected - 1 || writebacks != 0 {
        return Err(Error::Count);
    }
    Ok(Summary {
        accesses: EVENTS,
        hits,
        misses,
        root_misses,
        child_misses,
        writebacks,
        hit_by_event,
    })
}

#[cfg(test)]
mod tests {
    use super::super::truth::{ALL, expected_events};
    use super::*;
    const DATA: u64 = 0x2080;
    const RSP: u64 = 0x3fe8;
    fn events(case: Case) -> Vec<Event> {
        expected_events(case, 17, 0x1000, DATA, RSP, 0x5000).unwrap()
    }
    #[test]
    fn tree_model_one_cache_exact_literal_vectors_and_attribution() {
        for (case, misses) in ALL.into_iter().zip([3, 65]) {
            let got = check(case, DATA, RSP, &events(case)).unwrap();
            assert_eq!(
                (
                    got.accesses,
                    got.hits,
                    got.misses,
                    got.root_misses,
                    got.child_misses,
                    got.writebacks
                ),
                (132, 132 - misses, misses, 1, misses - 1, 0)
            );
            let positions: Vec<_> = got
                .hit_by_event
                .iter()
                .enumerate()
                .filter_map(|(i, &h)| (!h).then_some(i))
                .collect();
            let expected = if case == Case::Fit2 {
                vec![0, 1, 4]
            } else {
                [vec![0, 1], (1..64).map(|i| 2 + 2 * i).collect()].concat()
            };
            assert_eq!(positions, expected);
            assert_eq!(&got.hit_by_event[130..], [true, true]);
            // New invocations start invalid once, with identical full bit vectors.
            assert_eq!(got, check(case, DATA, RSP, &events(case)).unwrap());
        }
    }
    #[test]
    fn tree_model_no_write_allocate_and_child_reset_are_observable() {
        let e = events(Case::Fit2);
        let good = check(Case::Fit2, DATA, RSP, &e).unwrap().hit_by_event;
        // Removing CALL allocation simulates the demand cache of a no-allocate store.
        let mut no_allocate = vec![false];
        no_allocate.extend(demand(&e[1..]).0);
        assert!(!no_allocate[130]);
        assert_ne!(good, no_allocate);
        // Resetting on child entry loses the already allocated stack line too.
        let reset = [demand(&e[..1]).0, demand(&e[1..]).0].concat();
        assert!(!reset[130]);
        assert_ne!(good, reset);
        // Resetting each function and adding totals double-counts cold stack work.
        let parent: Vec<_> = e.iter().copied().filter(|e| e.node == ROOT_NODE).collect();
        let child: Vec<_> = e.iter().copied().filter(|e| e.node == CHILD_NODE).collect();
        let isolated_misses = demand(&parent).0.iter().filter(|&&h| !h).count()
            + demand(&child).0.iter().filter(|&&h| !h).count();
        assert_eq!(isolated_misses, 4);
        assert_ne!(
            isolated_misses,
            check(Case::Fit2, DATA, RSP, &e).unwrap().misses
        );
    }
    #[test]
    fn tree_model_missing_reordered_wrong_function_and_kind_refuse() {
        let original = events(Case::Fit2);
        for index in 0..EVENTS {
            let mut changed = original.clone();
            changed.remove(index);
            assert_eq!(check(Case::Fit2, DATA, RSP, &changed), Err(Error::Trace));
            let mut changed = original.clone();
            changed.insert(index, original[index]);
            assert_eq!(check(Case::Fit2, DATA, RSP, &changed), Err(Error::Trace));
            let mut changed = original.clone();
            changed[index].node ^= 1;
            assert_eq!(check(Case::Fit2, DATA, RSP, &changed), Err(Error::Trace));
            let mut changed = original.clone();
            changed[index].kind = if changed[index].kind == EventKind::Count {
                EventKind::Link
            } else {
                EventKind::Count
            };
            assert_eq!(check(Case::Fit2, DATA, RSP, &changed), Err(Error::Trace));
        }
        for (a, b) in [(0, 1), (2, 3), (130, 131)] {
            let mut changed = original.clone();
            changed.swap(a, b);
            assert_eq!(check(Case::Fit2, DATA, RSP, &changed), Err(Error::Trace));
        }
        assert_eq!(
            check(Case::Conflict3, DATA, RSP, &original),
            Err(Error::Trace)
        );
        for index in [0, 1, 3, 130] {
            let mut changed = original.clone();
            changed[index].value ^= 1;
            assert_eq!(check(Case::Fit2, DATA, RSP, &changed), Err(Error::Trace));
        }
    }
    #[test]
    fn tree_model_every_foreign_address_width_and_geometry_refuses() {
        let original = events(Case::Fit2);
        for i in 0..EVENTS {
            let mut changed = original.clone();
            changed[i].address += 1024;
            assert_eq!(check(Case::Fit2, DATA, RSP, &changed), Err(Error::Trace));
            for width in [0, 1, 4, 16] {
                let mut changed = original.clone();
                changed[i].width = width;
                assert_eq!(check(Case::Fit2, DATA, RSP, &changed), Err(Error::Address));
            }
            for address in [DATA + 1, DATA + 60, u64::MAX - 3] {
                let mut changed = original.clone();
                changed[i].address = address;
                assert_eq!(check(Case::Fit2, DATA, RSP, &changed), Err(Error::Address));
            }
        }
        for (data, rsp) in [
            (DATA + 1, RSP),
            (DATA + 64, RSP),
            (DATA, RSP - 64),
            (DATA, DATA + 24),
            (DATA, 8),
            (DATA, 0x3fc8),
            (u64::MAX - 63, RSP),
        ] {
            assert_eq!(check(Case::Fit2, data, rsp, &original), Err(Error::Address));
        }
        // All high bits participate; there is no remapping onto low-address lines.
        let high_data = DATA + (1_u64 << 32);
        let high_rsp = RSP + (1_u64 << 33);
        let high = expected_events(Case::Fit2, 17, 0x1000, high_data, high_rsp, 0x5000).unwrap();
        assert_eq!(
            check(Case::Fit2, high_data, high_rsp, &high).unwrap(),
            check(Case::Fit2, DATA, RSP, &original).unwrap()
        );
    }
    #[test]
    fn tree_model_lru_and_dirty_state_kernel_controls() {
        // MRU update distinguishes LRU from FIFO. This is a model-only control.
        let mut e: Vec<_> = [0, 4, 0, 8, 4]
            .into_iter()
            .map(|line| Event {
                node: ROOT_NODE,
                kind: EventKind::Payload,
                address: line * 64,
                width: 8,
                value: 0,
            })
            .collect();
        assert_eq!(demand(&e).0, [false, false, true, false, false]);
        assert_eq!(demand(&e).0, reuse_distance(&e));
        e[1].kind = EventKind::CallStore; // dirty4 becomes LRU at the third use
        assert_eq!(demand(&e).1, 1);
    }
}
