//! Join actual closed postflight values to the already paired native boundaries.
//! Counts describe original source instructions, not elapsed time or counters.
use super::witness::{MAGIC, WORDS, Witness};
use super::*;
pub const CSV_HEADER: &str = "k,seed,case,scenario,pid,tid,registration,install,batch,node,function,ordinal,parent_ordinal,entry_pc,return_pc,entry_rsp,return_word,resume_pc,resume_rsp,value,owner,generation,invocation_plus_one,rank_plus_one,history_prefix,sequence_before,actual_children,sampled_children_plus_one,ack,caller_entry,own_body_instructions,inclusive_body_instructions,entry_to_pre_ret_instructions\n";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkRow([u64; 33]);
impl WorkRow {
    pub fn values(&self) -> [u64; 33] {
        self.0
    }
}
#[derive(Clone, Copy, Debug)]
struct Frame {
    entry: u64,
    ret: u64,
    rsp: u64,
    word: u64,
    resume: u64,
    resume_rsp: u64,
    value: u64,
    own: u64,
    inclusive: u64,
    pre_ret: u64,
}
fn frames(ready: &Ready, points: &[Snapshot], trace: &Trace) -> [Frame; 2] {
    assert!(!points.is_empty() && points.len() <= MAX_STEPS);
    let unique = |pc| {
        let mut found = points
            .iter()
            .enumerate()
            .filter(|(_, p)| p.logical_pc == pc);
        let i = found.next().expect("missing actual boundary").0;
        assert!(found.next().is_none(), "duplicate actual boundary");
        i
    };
    let starts = ready.functions.each_ref().map(|f| unique(f.entry));
    let ends = [
        unique(ready.parent().returns[0]),
        unique(ready.child().entry + trace.child.ret_offset),
    ];
    assert!(starts[0] < starts[1] && starts[1] <= ends[1] && ends[1] < ends[0]);
    let parent = ready.parent_plan();
    assert_eq!(
        points[starts[1] - 1].logical_pc,
        ready.parent().entry + parent.call
    );
    assert_eq!(
        points[ends[1] + 1].logical_pc,
        ready.parent().entry + parent.continuation
    );
    assert_eq!(
        points[ends[0] + 1].logical_pc,
        ready.caller + ready.plan.continuations()[0]
    );
    let caller_rsp = points[starts[0]]
        .registers
        .rsp
        .checked_add(ready.plan.subject_rsp_delta())
        .unwrap();
    let stack = caller_rsp
        .checked_sub(trace.stack_bytes.checked_sub(8).unwrap())
        .unwrap();
    let frames = std::array::from_fn(|node| {
        let body = &points[starts[node]..=ends[node]];
        let f = &ready.functions[node];
        assert!(f.returns.contains(&body.last().unwrap().logical_pc));
        assert!(body.iter().all(|p| {
            f.heads.contains(&p.logical_pc)
                || (node == 0 && ready.child().heads.contains(&p.logical_pc))
        }));
        let before = &points[starts[node]];
        let ret = &points[ends[node]];
        let after = &points[ends[node] + 1];
        assert_eq!(before.application_stack.len(), trace.stack_bytes as usize);
        assert_eq!(ret.registers.rsp, before.registers.rsp);
        let word = word_at(&before.application_stack, stack, before.registers.rsp);
        assert_eq!(
            word_at(&ret.application_stack, stack, ret.registers.rsp),
            word
        );
        assert_eq!(after.logical_pc, word);
        assert_eq!(
            after.registers.rsp,
            before.registers.rsp.checked_add(8).unwrap()
        );
        Frame {
            entry: before.logical_pc,
            ret: ret.logical_pc,
            rsp: before.registers.rsp,
            word,
            resume: after.logical_pc,
            resume_rsp: after.registers.rsp,
            value: ret.registers.rax,
            own: body
                .iter()
                .filter(|p| f.heads.contains(&p.logical_pc))
                .count() as u64,
            inclusive: body.len() as u64,
            pre_ret: (ends[node] - starts[node]) as u64,
        }
    });
    assert_eq!(frames[0].own, trace.parent_visits as u64);
    assert_eq!(frames[1].own, trace.child.visits as u64);
    assert_eq!(
        frames[0].inclusive,
        frames[0].own.checked_add(frames[1].own).unwrap()
    );
    assert_eq!(frames[1].inclusive, frames[1].own);
    for f in frames {
        assert_eq!(f.pre_ret, f.inclusive.checked_sub(1).unwrap());
    }
    frames
}
fn expected_header(seed: u64, ready: &Ready, pid: u32) -> [u64; 16] {
    let case = ready.case;
    let index = keys()
        .iter()
        .position(|key| *key == (case.k, seed, case.index, case.scenario))
        .unwrap();
    [
        MAGIC,
        1,
        WORDS as u64,
        index as u64,
        seed,
        case.k as u64,
        case.index as u64,
        case.scenario.id(),
        u64::from(pid),
        case.selections[0],
        case.extents[0] as u64,
        case.selections[1],
        case.extents[1] as u64,
        ready.caller,
        ready.plan.bytes().len() as u64,
        0,
    ]
}
fn expected_stream(ready: &Ready, pid: u32) -> [u64; 16] {
    let parent = ready.parent_plan();
    [
        u64::from(pid),
        INSTALL,
        0xc5c5_c5c5_c5c5_c5c5,
        0xc5c5_c5c5_c5c5_c5c5,
        0xc5c5_c5c5_c5c5_c5c5,
        0xc5c5_c5c5_c5c5_c5c5,
        ready.parent().entry,
        1,
        FUNCTIONS[0],
        FUNCTIONS[1],
        ready.parent().entry,
        ready.child().entry,
        ready.parent().entry + parent.call,
        ready.child().entry,
        ready.parent().entry + parent.continuation,
        1,
    ]
}
fn records(ready: &Ready, frames: &[Frame; 2], w: &Witness) {
    let j = ready.journal.as_ref().unwrap();
    for (n, (r, f)) in w.rows.iter().zip(frames).enumerate() {
        assert_eq!(
            &r[..6],
            &[FUNCTIONS[n], n as u64, 1, n as u64 + 1, f.entry, f.ret]
        );
        assert_eq!(
            &r[13..22],
            &[
                f.rsp,
                f.word,
                f.resume,
                f.resume_rsp,
                f.value,
                if n == 0 { 2 } else { 1 },
                if n == 0 || ready.case.scenario == Scenario::StableA {
                    1
                } else {
                    2
                },
                0,
                u64::from(n == 0)
            ]
        );
        let sampled = n == 0 || ready.case.scenario.sampled_child();
        if sampled {
            let generation = if n == 0 {
                j.a_generation
            } else {
                j.b_generation.unwrap_or(j.a_generation)
            };
            let slot = u64::from(n == 1 && ready.case.scenario == Scenario::StableA);
            assert_eq!(&r[6..9], &[1, generation, slot]);
            let children = u64::from(n == 0 && ready.case.scenario.sampled_child());
            assert_eq!(&r[22..24], &[1, children]);
            let admission = [generation, slot, FUNCTIONS[n], r[9]];
            assert_eq!(r[24], 1);
            assert_eq!(&r[25..29], &admission);
            assert_eq!(&r[29..36], &[1, 0, 0, 0, 0, 0, 0]);
            assert_eq!(r[36], 1);
            assert_eq!(&r[37..41], &admission);
            // Timestamp observations are not parent-known truth. Only their
            // existing AUX-before-reversal outcome and cross-copy joins apply.
            let (tag, end) = if r[10] != r[12] {
                (2, 1)
            } else if r[11] < r[9] {
                (2, 2)
            } else {
                (1, r[11])
            };
            assert_eq!(&r[41..48], &[1, 0, 1, tag, end, children, 0]);
        } else {
            assert_eq!(&r[6..9], &[3, j.a_generation, 0]);
            assert!(r[22..].iter().all(|&v| v == 0));
        }
    }
}
fn reports(ready: &Ready, w: &Witness) {
    let j = ready.journal.as_ref().unwrap();
    assert_eq!(w.report_count, if j.b_generation.is_some() { 2 } else { 1 });
    let mut joined = 0;
    for (i, report) in w.reports.iter().take(w.report_count as usize).enumerate() {
        let generation = if i == 0 {
            j.a_generation
        } else {
            j.b_generation.unwrap()
        };
        assert_eq!(report[0], generation);
        let expected: Vec<_> = w
            .rows
            .iter()
            .filter(|r| r[6] == 1 && r[7] == generation)
            .collect();
        assert_eq!(report[1] as usize, expected.len());
        for (slot, (record, row)) in report[2..].chunks_exact(22).zip(expected).enumerate() {
            assert_eq!(row[8], slot as u64);
            assert_eq!(&record[..4], &row[25..29]);
            assert_eq!(&record[4..10], &[1, 1, slot as u64, 1, 0, 0]);
            assert_eq!(&record[10..22], &row[36..48]);
            joined += 1;
        }
    }
    assert_eq!(joined, 1 + usize::from(ready.case.scenario.sampled_child()));
}
fn history(ready: &Ready, w: &Witness) {
    assert_eq!(&w.history[..16], &w.stream);
    let j = ready.journal.as_ref().unwrap();
    let (count, last) = if let Some(b) = j.b_generation {
        (3, b)
    } else {
        (2, j.a_generation)
    };
    assert_eq!(
        &w.history[16..26],
        &[1, 0, count, 0, 0, 0, 2, count - 1, last, count]
    );
    let published = |g| [1, g, 0, 0, 1, g, 0, 0];
    let removed = |g| [2, g, 0, 0, 0, 0, 0, 0];
    assert_eq!(&w.history[26..34], &published(j.a_generation));
    if let Some(b) = j.b_generation {
        assert_eq!(&w.history[34..42], &published(b));
        assert_eq!(&w.history[42..50], &removed(b));
    } else {
        assert_eq!(&w.history[34..42], &removed(j.a_generation));
        assert_eq!(&w.history[42..50], &[0; 8]);
    }
}
fn join_values(
    seed: u64,
    ready: &Ready,
    pid: u32,
    frames: &[Frame; 2],
    w: &Witness,
) -> [WorkRow; 2] {
    assert_eq!(w.header, expected_header(seed, ready, pid));
    assert_eq!(
        &w.batch[..6],
        &[
            u64::from(pid),
            u64::from(pid),
            1,
            INSTALL,
            1,
            match ready.case.scenario {
                Scenario::StableA => 1,
                Scenario::RearmB => 3,
                Scenario::RemovedChild => 2,
            }
        ]
    );
    assert_eq!(&w.batch[6..13], &[0; 7]);
    let child = u64::from(ready.case.scenario.sampled_child());
    assert_eq!(&w.batch[13..20], &[1, 1, 2, 2, 2, 1 + child, 1 - child]);
    assert_eq!(w.stream, expected_stream(ready, pid));
    records(ready, frames, w);
    reports(ready, w);
    history(ready, w);
    std::array::from_fn(|n| {
        let r = &w.rows[n];
        let f = &frames[n];
        WorkRow([
            ready.case.k as u64,
            seed,
            ready.case.index as u64 + 1,
            ready.case.scenario.id(),
            w.batch[0],
            w.batch[1],
            w.batch[2],
            w.batch[3],
            w.batch[4],
            r[1],
            r[0],
            r[3],
            r[2],
            r[4],
            r[5],
            r[13],
            r[14],
            r[15],
            r[16],
            r[17],
            r[6],
            r[7],
            if r[6] == 1 {
                r[8].checked_add(1).unwrap()
            } else {
                0
            },
            if r[24] == 1 {
                r[30].checked_add(1).unwrap()
            } else {
                0
            },
            r[19],
            r[20],
            r[21],
            if r[22] == 1 {
                r[23].checked_add(1).unwrap()
            } else {
                0
            },
            r[18],
            ready.caller,
            f.own,
            f.inclusive,
            f.pre_ret,
        ])
    })
}
pub(super) fn join(
    seed: u64,
    original: &Ready,
    candidate: &Ready,
    points: &[Snapshot],
    trace: &Trace,
    (pid, bytes): (u32, &[u8]),
) -> [WorkRow; 2] {
    original.same_source(candidate);
    assert!(original.journal.is_none() && candidate.journal.is_some());
    let reference = frames(original, points, trace);
    let actual = witness::decode(bytes);
    join_values(seed, candidate, pid, &reference, &actual)
}
#[cfg(test)]
#[path = "trace_join/tests.rs"]
mod tests;
