//! Exact normal-state two-call row/journal predicate, also compiled by calibration target.
use crate::oracle::native_ordinary::normal_caller::caller_bytes::{
    CONTINUATIONS, SUBJECT_RSP_DELTA,
};
use rapid_profiler::frontend_native::{NormalAcknowledgement, NormalRecord, RawIntervalOwner};

pub(super) struct Facts<'a> {
    pub(super) entry: u64,
    pub(super) returns: &'a [u64],
    pub(super) caller: u64,
    pub(super) caller_rsp: u64,
    pub(super) generations: [u64; 2],
    pub(super) crossed: bool,
    pub(super) tid: u64,
}
pub(super) fn rows_match(rows: &[NormalRecord], journal: &[u64], f: &Facts<'_>) -> bool {
    if rows.len() != 2
        || journal.len() != 512
        || f.generations.contains(&0)
        || (f.crossed != (f.generations[0] != f.generations[1]))
        || rows[0].raw.return_pc != rows[1].raw.return_pc
    {
        return false;
    }
    let mut expected = [0_u64; 512];
    expected[..4].copy_from_slice(&[4, 0, f.tid, 0]);
    for (i, row) in rows.iter().enumerate() {
        let ordinal = i as u64 + 1;
        let invocation = if f.crossed { 0 } else { i };
        let prefix = if f.crossed && i == 1 { 3 } else { 1 };
        let acknowledgement = if i == 0 {
            NormalAcknowledgement::NextEntry { ordinal: 2 }
        } else {
            NormalAcknowledgement::CallerCheckpoint
        };
        if row.raw.ordinal != ordinal
            || row.raw.entry_pc != f.entry
            || !f.returns.contains(&row.raw.return_pc)
            || row.raw.owner
                != (RawIntervalOwner::Sampled {
                    generation: f.generations[i],
                    invocation,
                })
            || row.entry_rsp != f.caller_rsp - SUBJECT_RSP_DELTA
            || row.return_word != f.caller + CONTINUATIONS[i]
            || row.history_prefix != prefix
            || row.acknowledgement != acknowledgement
        {
            return false;
        }
        let packed = (invocation as u64 + 1) | (prefix << 13);
        for (n, pc) in [row.raw.entry_pc, row.raw.return_pc]
            .into_iter()
            .enumerate()
        {
            let at = 4 + (2 * i + n) * 7;
            expected[at..at + 7].copy_from_slice(&[
                n as u64 + 1,
                ordinal,
                pc,
                row.entry_rsp,
                row.return_word,
                f.generations[i],
                packed,
            ]);
        }
    }
    journal == expected
}

#[cfg(test)]
mod tests {
    use super::*;
    use rapid_profiler::frontend_native::{RawInterval, RawTimestamp};
    fn fixture(crossed: bool) -> (Vec<NormalRecord>, [u64; 512]) {
        let rows = (0..2)
            .map(|i| NormalRecord {
                raw: RawInterval {
                    ordinal: i + 1,
                    entry_pc: 0x1000,
                    return_pc: 0x1020,
                    owner: RawIntervalOwner::Sampled {
                        generation: if crossed && i == 1 { 9 } else { 7 },
                        invocation: if crossed { 0 } else { i as usize },
                    },
                    start: RawTimestamp {
                        ticks: 10 + i * 10,
                        aux: 3,
                    },
                    end: RawTimestamp {
                        ticks: 15 + i * 10,
                        aux: 3,
                    },
                },
                entry_rsp: 0x8000 - 48,
                return_word: 0x2000 + CONTINUATIONS[i as usize],
                history_prefix: if crossed && i == 1 { 3 } else { 1 },
                acknowledgement: if i == 0 {
                    NormalAcknowledgement::NextEntry { ordinal: 2 }
                } else {
                    NormalAcknowledgement::CallerCheckpoint
                },
            })
            .collect::<Vec<_>>();
        let mut page = [0; 512];
        page[..4].copy_from_slice(&[4, 0, 23, 0]);
        for (i, r) in rows.iter().enumerate() {
            for exit in 0..2 {
                let at = 4 + (i * 2 + exit) * 7;
                let g = if crossed && i == 1 { 9 } else { 7 };
                let bits = (if crossed { 1 } else { i as u64 + 1 })
                    | ((if crossed && i == 1 { 3 } else { 1 }) << 13);
                page[at..at + 7].copy_from_slice(&[
                    exit as u64 + 1,
                    i as u64 + 1,
                    if exit == 0 { 0x1000 } else { 0x1020 },
                    r.entry_rsp,
                    r.return_word,
                    g,
                    bits,
                ]);
            }
        }
        (rows, page)
    }
    fn facts(crossed: bool) -> Facts<'static> {
        Facts {
            entry: 0x1000,
            returns: &[0x1020],
            caller: 0x2000,
            caller_rsp: 0x8000,
            generations: if crossed { [7, 9] } else { [7, 7] },
            crossed,
            tid: 23,
        }
    }
    #[test]
    fn normal_native_rows_require_exact_next_entry_and_checkpoint() {
        for crossed in [false, true] {
            let (rows, page) = fixture(crossed);
            assert!(rows_match(&rows, &page, &facts(crossed)));
            for ack in [
                NormalAcknowledgement::CallerCheckpoint,
                NormalAcknowledgement::NextEntry { ordinal: 3 },
            ] {
                let mut bad = rows.clone();
                bad[0].acknowledgement = ack;
                assert!(!rows_match(&bad, &page, &facts(crossed)));
            }
            let mut bad = rows;
            bad[1].acknowledgement = NormalAcknowledgement::NextEntry { ordinal: 3 };
            assert!(!rows_match(&bad, &page, &facts(crossed)));
        }
    }
    #[test]
    fn normal_native_rows_bind_continuation_owner_prefix_and_complete_journal() {
        for crossed in [false, true] {
            let (rows, page) = fixture(crossed);
            for index in 0..2 {
                let at = 4 + index * 14;
                // Keep both journal endpoints consistent with each forged row:
                // these isolate external continuation/owner/prefix/stack joins.
                let mut bad = rows.clone();
                let mut words = page;
                bad[index].return_word += 1;
                words[at + 4] += 1;
                words[at + 11] += 1;
                assert!(!rows_match(&bad, &words, &facts(crossed)));
                let mut bad = rows.clone();
                let mut words = page;
                bad[index].history_prefix += 1;
                words[at + 6] += 1 << 13;
                words[at + 13] += 1 << 13;
                assert!(!rows_match(&bad, &words, &facts(crossed)));
                let mut bad = rows.clone();
                let mut words = page;
                bad[index].entry_rsp += 16;
                words[at + 3] += 16;
                words[at + 10] += 16;
                assert!(!rows_match(&bad, &words, &facts(crossed)));
                let mut bad = rows.clone();
                let mut words = page;
                bad[index].raw.owner = RawIntervalOwner::FunctionClosed {
                    generation: words[at + 5],
                };
                words[at] = 3;
                words[at + 7] = 4;
                words[at + 6] = (bad[index].history_prefix << 13) | (3 << 22);
                words[at + 13] = words[at + 6];
                assert!(!rows_match(&bad, &words, &facts(crossed)));
            }
            for index in 0..512 {
                let mut bad = page;
                bad[index] ^= 1;
                assert!(!rows_match(&rows, &bad, &facts(crossed)));
            }
            assert!(!rows_match(&rows[..1], &page, &facts(crossed)));
            assert!(!rows_match(&rows, &page[..511], &facts(crossed)));
        }
    }
}
