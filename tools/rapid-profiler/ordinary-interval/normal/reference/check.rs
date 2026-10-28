//! Fixed48-row joins. No invocation, return witness, calibration or duration truth.
use super::bytes;
use crate::exact::truth;
use rapid_profiler::frontend::{
    ActionKind, ControllerSnapshot, ControllerStatus, Observation, PayloadOutcome,
    RecordObservation, Report,
};
use rapid_profiler::frontend_native::{
    NormalAcknowledgement, NormalBatch, NormalRecord, NormalTotals, RawIntervalOwner,
};
use rapid_profiler::generation::{Disposition, FunctionId, Terminal};

const CALLS: usize = 24;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Identity,
    Population,
    Clock,
    Stack,
    Record,
    Journal,
    Report,
    History,
}
type Result<T> = std::result::Result<T, Error>;
fn require(ok: bool, error: Error) -> Result<()> {
    if ok { Ok(()) } else { Err(error) }
}

/// Predeclared identities plus the actual generation returned by stage().
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Expected {
    pub pid: u32,
    pub tid: u64,
    pub install: u64,
    pub function: FunctionId,
    pub registration: u64,
    pub entry: u64,
    pub caller: u64,
    pub generation: u64,
}
/// Copied only after actual helper return and all consumer postflight checks.
/// There are deliberately no original SDK record/owner/ordinal fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Collected {
    pub seed_index: usize,
    pub length: usize,
    pub value: u64,
    pub reference: bytes::ReturnedView,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Gaps {
    pub enclosure: u64,
    pub raw: u64,
    pub entry: u64,
    pub exit: u64,
}
fn gaps(r: bytes::Enclosure, row: &NormalRecord) -> Result<Gaps> {
    require(
        [r.end.aux, row.raw.start.aux, row.raw.end.aux]
            .iter()
            .all(|&aux| aux == r.start.aux),
        Error::Clock,
    )?;
    let enclosure = r.end.ticks.checked_sub(r.start.ticks).ok_or(Error::Clock)?;
    let entry = row
        .raw
        .start
        .ticks
        .checked_sub(r.start.ticks)
        .ok_or(Error::Clock)?;
    let raw = row
        .raw
        .end
        .ticks
        .checked_sub(row.raw.start.ticks)
        .ok_or(Error::Clock)?;
    let exit = r
        .end
        .ticks
        .checked_sub(row.raw.end.ticks)
        .ok_or(Error::Clock)?;
    require(
        entry.checked_add(raw).and_then(|v| v.checked_add(exit)) == Some(enclosure),
        Error::Clock,
    )?;
    Ok(Gaps {
        enclosure,
        raw,
        entry,
        exit,
    })
}

fn collected(originals: &[Collected], installed: &[Collected]) -> Result<()> {
    require(
        originals.len() == CALLS && installed.len() == CALLS,
        Error::Population,
    )?;
    let mut previous = None;
    let mut aux = None;
    for (leg, rows) in [originals, installed].into_iter().enumerate() {
        for (i, row) in rows.iter().enumerate() {
            let seed_index = (i % 8) / 4;
            let length = if (i / 2) % 2 == 0 { 1 } else { 64 };
            let input: [u8; 64] = std::array::from_fn(|j| (37 * j + 11 + seed_index) as u8);
            let value = truth::checksum(&input[..length]).map_err(|_| Error::Record)?;
            let literal = input[..length]
                .iter()
                .map(|b| u64::from(b ^ 0x5a))
                .sum::<u64>()
                ^ 0x9e37_79b9_7f4a_7c15;
            require(
                value == literal
                    && row.seed_index == seed_index
                    && row.length == length
                    && row.value == value,
                Error::Record,
            )?;
            let view = row.reference;
            require(
                view.external_id == i as u64 + 1 && view.sequence == (leg * CALLS + i + 1) as u64,
                Error::Identity,
            )?;
            let p = view.observed_pre_call_rsp;
            require(
                p != 0
                    && p % 16 == 0
                    && p.checked_sub(136).is_some()
                    && p.checked_add(48).is_some()
                    && (i % 2 == 0 || p == rows[i - 1].reference.observed_pre_call_rsp),
                Error::Stack,
            )?;
            let r = view.enclosure;
            require(
                r.start.aux == r.end.aux
                    && r.start.ticks <= r.end.ticks
                    && aux.is_none_or(|a| a == r.start.aux)
                    && previous.is_none_or(|end| end <= r.start.ticks),
                Error::Clock,
            )?;
            aux = Some(r.start.aux);
            previous = Some(r.end.ticks);
        }
    }
    Ok(())
}

// A standalone process has one complete leg, with local identities 1..24.
// Keep collected() independent: its installed leg remains 25..48 and its
// chronology/AUX scope still crosses the original/installed boundary.
fn collected_leg(rows: &[Collected]) -> Result<()> {
    require(rows.len() == CALLS, Error::Population)?;
    let mut previous = None;
    let mut aux = None;
    for (i, row) in rows.iter().enumerate() {
        let seed_index = (i % 8) / 4;
        let length = if (i / 2) % 2 == 0 { 1 } else { 64 };
        let input: [u8; 64] = std::array::from_fn(|j| (37 * j + 11 + seed_index) as u8);
        let value = truth::checksum(&input[..length]).map_err(|_| Error::Record)?;
        let literal = input[..length]
            .iter()
            .map(|b| u64::from(b ^ 0x5a))
            .sum::<u64>()
            ^ 0x9e37_79b9_7f4a_7c15;
        require(
            value == literal
                && row.seed_index == seed_index
                && row.length == length
                && row.value == value,
            Error::Record,
        )?;
        let view = row.reference;
        require(
            view.external_id == i as u64 + 1 && view.sequence == i as u64 + 1,
            Error::Identity,
        )?;
        let p = view.observed_pre_call_rsp;
        require(
            p != 0
                && p % 16 == 0
                && p.checked_sub(136).is_some()
                && p.checked_add(48).is_some()
                && (i % 2 == 0 || p == rows[i - 1].reference.observed_pre_call_rsp),
            Error::Stack,
        )?;
        let r = view.enclosure;
        require(
            r.start.aux == r.end.aux
                && r.start.ticks <= r.end.ticks
                && aux.is_none_or(|a| a == r.start.aux)
                && previous.is_none_or(|end| end <= r.start.ticks),
            Error::Clock,
        )?;
        aux = Some(r.start.aux);
        previous = Some(r.end.ticks);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Metadata {
    legacy: bool,
    pid: u32,
    tid: u64,
    registration: u64,
    install: u64,
    function: FunctionId,
    number: u64,
    totals: (NormalTotals, NormalTotals),
    sequences: (u64, u64),
    next: u64,
}
struct Parts<'a> {
    meta: Metadata,
    rows: &'a [NormalRecord],
    journal: &'a [u64],
    report_generation: u64,
    reports: &'a [RecordObservation],
    history: &'a ControllerSnapshot,
}
fn complete() -> NormalTotals {
    NormalTotals {
        entered: 24,
        ret_observed: 24,
        confirmed: 24,
        completed: 24,
        unsampled: 0,
    }
}
fn identity(e: Expected) -> Result<()> {
    require(
        e.pid != 0
            && e.tid == u64::from(e.pid)
            && e.install != 0
            && e.registration == 1
            && e.generation != 0
            && e.entry != 0
            && e.caller != 0
            && e.entry.checked_add(37).is_some()
            && e.caller.checked_add(295).is_some(),
        Error::Identity,
    )
}
fn all(
    e: Expected,
    originals: &[Collected],
    installed: &[Collected],
    p: Parts<'_>,
) -> Result<[Gaps; CALLS]> {
    identity(e)?;
    collected(originals, installed)?;
    installed_join(e, installed, p)
}
fn installed_join(e: Expected, installed: &[Collected], p: Parts<'_>) -> Result<[Gaps; CALLS]> {
    require(
        p.meta
            == Metadata {
                legacy: true,
                pid: e.pid,
                tid: e.tid,
                registration: e.registration,
                install: e.install,
                function: e.function,
                number: 1,
                totals: (NormalTotals::default(), complete()),
                sequences: (0, 24),
                next: 25,
            },
        Error::Identity,
    )?;
    require(
        p.rows.len() == CALLS && p.reports.len() == CALLS,
        Error::Population,
    )?;
    require(p.report_generation == e.generation, Error::Report)?;
    let mut journal = [0; 512];
    journal[..4].copy_from_slice(&[48, 0, e.tid, 0]);
    let mut result = [Gaps::default(); CALLS];
    for i in 0..CALLS {
        let row = &p.rows[i];
        let ordinal = i as u64 + 1;
        require(
            row.raw.ordinal == ordinal
                && row.raw.entry_pc == e.entry
                && row.raw.return_pc == e.entry + 36
                && row.raw.owner
                    == RawIntervalOwner::Sampled {
                        generation: e.generation,
                        invocation: i,
                    }
                && row.history_prefix == 1
                && row.acknowledgement
                    == (if i + 1 == CALLS {
                        NormalAcknowledgement::CallerCheckpoint
                    } else {
                        NormalAcknowledgement::NextEntry {
                            ordinal: ordinal + 1,
                        }
                    }),
            Error::Record,
        )?;
        require(
            row.entry_rsp % 16 == 8
                && row.entry_rsp.checked_add(8)
                    == Some(installed[i].reference.observed_pre_call_rsp)
                && row.return_word == e.caller + bytes::CONTINUATIONS[i % 2],
            Error::Stack,
        )?;
        result[i] = gaps(installed[i].reference.enclosure, row)?;
        let bits = ordinal | (1 << 13);
        let at = 4 + i * 14;
        journal[at..at + 7].copy_from_slice(&[
            1,
            ordinal,
            e.entry,
            row.entry_rsp,
            row.return_word,
            e.generation,
            bits,
        ]);
        journal[at + 7..at + 14].copy_from_slice(&[
            2,
            ordinal,
            e.entry + 36,
            row.entry_rsp,
            row.return_word,
            e.generation,
            bits,
        ]);
        let observed = p.reports[i];
        let admission = observed.record.admission;
        require(
            admission.generation.get() == e.generation
                && admission.function == e.function
                && admission.invocation == i
                && admission.entry_value == row.raw.start.ticks
                && observed.record.terminal
                    == Some(Terminal::Completed {
                        value: i as u64,
                        disposition: Disposition::Retained { rank: i },
                    }),
            Error::Report,
        )?;
        let payload = observed.payload.ok_or(Error::Report)?;
        require(
            payload.admission == admission
                && payload.thread == e.registration
                && payload.start_sequence == i as u64
                && payload.outcome
                    == PayloadOutcome::Completed {
                        end: Observation::Value(row.raw.end.ticks),
                        completed_children: 0,
                    },
            Error::Report,
        )?;
    }
    require(p.journal == journal, Error::Journal)?;
    let h = p.history;
    require(
        h.status == ControllerStatus::Ready
            && h.current.is_none()
            && h.enabled == [true]
            && h.retained_failed_generation.is_none()
            && h.actions.len() == 2,
        Error::History,
    )?;
    for (i, action) in h.actions.iter().enumerate() {
        require(
            action.generation.get() == e.generation
                && action.function.is_none()
                && action.group.is_none()
                && action.kind
                    == (if i == 0 {
                        ActionKind::Published
                    } else {
                        ActionKind::Removed
                    })
                && action.current.map(|g| g.get())
                    == (if i == 0 { Some(e.generation) } else { None }),
            Error::History,
        )?;
    }
    Ok(result)
}

/// No mutation/receipt consumption. Call only after actual returns, full consumer
/// postflight, one checkpoint transfer, empty checkpoint, detach and disarm.
/// It joins independent immutable SDK data to cell stores; neither input alone
/// establishes the enclosing helper's physical return or body-duration accuracy.
pub(super) fn validate(
    e: Expected,
    originals: &[Collected],
    installed: &[Collected],
    batch: &NormalBatch,
    report: &Report,
    history: &ControllerSnapshot,
) -> Result<[Gaps; CALLS]> {
    let reports: Vec<_> = report.records().collect();
    all(
        e,
        originals,
        installed,
        Parts {
            meta: Metadata {
                legacy: batch.history_stream().is_none() && batch.history_high_water().is_none(),
                pid: batch.pid(),
                tid: batch.tid(),
                registration: batch.registration(),
                install: batch.install(),
                function: batch.function(),
                number: batch.number(),
                totals: batch.totals(),
                sequences: batch.completed_sequences(),
                next: batch.next_ordinal(),
            },
            rows: batch.records(),
            journal: batch.journal(),
            report_generation: report.generation().get(),
            reports: &reports,
            history,
        },
    )
}

/// Pure join only. The producer must already have authenticated the actual
/// helper return and complete source/input/cell postflight; these copied stores
/// do not independently prove a physical return or body-duration accuracy.
pub(super) fn validate_original_leg(rows: &[Collected]) -> Result<()> {
    collected_leg(rows)
}
fn all_installed_leg(e: Expected, rows: &[Collected], p: Parts<'_>) -> Result<[Gaps; CALLS]> {
    identity(e)?;
    collected_leg(rows)?;
    installed_join(e, rows, p)
}
/// Same actual-return/postflight/checkpoint/detach/disarm obligations as validate().
/// Local reference sequence and external ID are 1..24; no original SDK row exists.
pub(super) fn validate_installed_leg(
    e: Expected,
    rows: &[Collected],
    batch: &NormalBatch,
    report: &Report,
    history: &ControllerSnapshot,
) -> Result<[Gaps; CALLS]> {
    let reports: Vec<_> = report.records().collect();
    all_installed_leg(
        e,
        rows,
        Parts {
            meta: Metadata {
                legacy: batch.history_stream().is_none() && batch.history_high_water().is_none(),
                pid: batch.pid(),
                tid: batch.tid(),
                registration: batch.registration(),
                install: batch.install(),
                function: batch.function(),
                number: batch.number(),
                totals: batch.totals(),
                sequences: batch.completed_sequences(),
                next: batch.next_ordinal(),
            },
            rows: batch.records(),
            journal: batch.journal(),
            report_generation: report.generation().get(),
            reports: &reports,
            history,
        },
    )
}

#[cfg(test)]
mod leg_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use rapid_profiler::frontend::{Action, Payload};
    use rapid_profiler::frontend_native::{RawInterval, RawTimestamp};
    use rapid_profiler::generation::{Admission, Config, Epoch, Record};
    pub(super) struct Fixture {
        pub(super) e: Expected,
        pub(super) originals: Vec<Collected>,
        pub(super) installed: Vec<Collected>,
        pub(super) meta: Metadata,
        pub(super) rows: Vec<NormalRecord>,
        pub(super) journal: [u64; 512],
        pub(super) reports: Vec<RecordObservation>,
        pub(super) history: ControllerSnapshot,
    }
    impl Fixture {
        pub(super) fn check(&self) -> Result<[Gaps; 24]> {
            all(
                self.e,
                &self.originals,
                &self.installed,
                Parts {
                    meta: self.meta,
                    rows: &self.rows,
                    journal: &self.journal,
                    report_generation: self.e.generation,
                    reports: &self.reports,
                    history: &self.history,
                },
            )
        }
    }
    pub(super) fn fixture() -> Fixture {
        // Only allocate an opaque generation identity, never a fake native batch.
        let g = Epoch::new(
            &[FunctionId(1)],
            Config {
                retained_per_function: 24,
                max_inflight: 1,
                max_invocations: 24,
            },
        )
        .unwrap()
        .id();
        let e = Expected {
            pid: 17,
            tid: 17,
            install: 19,
            function: FunctionId(1),
            registration: 1,
            entry: 0x1000,
            caller: 0x2000,
            generation: g.get(),
        };
        let make = |leg: usize| {
            (0..24)
                .map(|i| {
                    let seed_index = (i % 8) / 4;
                    let length = if (i / 2) % 2 == 0 { 1 } else { 64 };
                    let value = (0..length)
                        .map(|j| u64::from(((37 * j + 11 + seed_index) as u8) ^ 0x5a))
                        .sum::<u64>()
                        ^ 0x9e37_79b9_7f4a_7c15;
                    let start = ((leg * 24 + i) * 100) as u64;
                    Collected {
                        seed_index,
                        length,
                        value,
                        reference: bytes::ReturnedView {
                            sequence: (leg * 24 + i + 1) as u64,
                            external_id: i as u64 + 1,
                            observed_pre_call_rsp: 0x8000,
                            enclosure: bytes::Enclosure {
                                start: bytes::Timestamp {
                                    ticks: start,
                                    aux: 3,
                                },
                                end: bytes::Timestamp {
                                    ticks: start + 90,
                                    aux: 3,
                                },
                            },
                        },
                    }
                })
                .collect::<Vec<_>>()
        };
        let originals = make(0);
        let installed = make(1);
        let mut rows = Vec::new();
        let mut reports = Vec::new();
        let mut journal = [0; 512];
        journal[..4].copy_from_slice(&[48, 0, 17, 0]);
        for (i, call) in installed.iter().enumerate() {
            let ordinal = i as u64 + 1;
            let raw = RawInterval {
                ordinal,
                entry_pc: e.entry,
                return_pc: e.entry + 36,
                owner: RawIntervalOwner::Sampled {
                    generation: g.get(),
                    invocation: i,
                },
                start: RawTimestamp {
                    ticks: call.reference.enclosure.start.ticks + 10,
                    aux: 3,
                },
                end: RawTimestamp {
                    ticks: call.reference.enclosure.end.ticks - 20,
                    aux: 3,
                },
            };
            let row = NormalRecord {
                raw,
                entry_rsp: 0x7ff8,
                return_word: e.caller + [80, 216][i % 2],
                history_prefix: 1,
                acknowledgement: if i == 23 {
                    NormalAcknowledgement::CallerCheckpoint
                } else {
                    NormalAcknowledgement::NextEntry {
                        ordinal: ordinal + 1,
                    }
                },
            };
            let admission = Admission {
                generation: g,
                invocation: i,
                function: e.function,
                entry_value: raw.start.ticks,
            };
            reports.push(RecordObservation {
                record: Record {
                    admission,
                    terminal: Some(Terminal::Completed {
                        value: i as u64,
                        disposition: Disposition::Retained { rank: i },
                    }),
                },
                payload: Some(Payload {
                    admission,
                    thread: 1,
                    start_sequence: i as u64,
                    outcome: PayloadOutcome::Completed {
                        end: Observation::Value(raw.end.ticks),
                        completed_children: 0,
                    },
                }),
            });
            let at = 4 + i * 14;
            let bits = ordinal | (1 << 13);
            journal[at..at + 7].copy_from_slice(&[
                1,
                ordinal,
                e.entry,
                row.entry_rsp,
                row.return_word,
                g.get(),
                bits,
            ]);
            journal[at + 7..at + 14].copy_from_slice(&[
                2,
                ordinal,
                e.entry + 36,
                row.entry_rsp,
                row.return_word,
                g.get(),
                bits,
            ]);
            rows.push(row);
        }
        Fixture {
            e,
            originals,
            installed,
            rows,
            reports,
            journal,
            meta: Metadata {
                legacy: true,
                pid: 17,
                tid: 17,
                registration: 1,
                install: 19,
                function: FunctionId(1),
                number: 1,
                totals: (NormalTotals::default(), complete()),
                sequences: (0, 24),
                next: 25,
            },
            history: ControllerSnapshot {
                status: ControllerStatus::Ready,
                current: None,
                enabled: vec![true],
                retained_failed_generation: None,
                actions: vec![
                    Action {
                        kind: ActionKind::Published,
                        generation: g,
                        function: None,
                        current: Some(g),
                        group: None,
                    },
                    Action {
                        kind: ActionKind::Removed,
                        generation: g,
                        function: None,
                        current: None,
                        group: None,
                    },
                ],
            },
        }
    }
    #[test]
    fn reference_population_requires_all48_ordered_case_identity_and_values() {
        let good = fixture();
        assert_eq!(
            good.check().unwrap(),
            [Gaps {
                enclosure: 90,
                raw: 60,
                entry: 10,
                exit: 20
            }; 24]
        );
        for k in 0..9 {
            let mut f = fixture();
            match k {
                0 => {
                    f.originals.pop();
                }
                1 => f.installed.push(f.installed[0]),
                2 => f.originals.swap(0, 1),
                3 => f.installed[0].reference.sequence -= 24,
                4 => f.installed[0].reference.external_id += 1,
                5 => f.originals[0].length = 64,
                6 => f.installed[0].seed_index = 1,
                7 => f.originals[0].value ^= 1,
                _ => f.installed[0].value ^= 1,
            }
            assert!(f.check().is_err(), "mutation{k}");
        }
    }
    #[test]
    fn reference_record_joins_stack_continuation_owner_ack_and_metadata() {
        for k in 0..13 {
            let mut f = fixture();
            match k {
                0 => f.rows[0].entry_rsp += 16,
                1 => f.rows[0].return_word += 1,
                2 => {
                    f.rows[0].raw.owner = RawIntervalOwner::FunctionClosed {
                        generation: f.e.generation,
                    }
                }
                3 => f.rows[0].raw.ordinal += 1,
                4 => f.rows[0].raw.entry_pc += 1,
                5 => f.rows[0].raw.return_pc -= 1,
                6 => f.rows[0].history_prefix += 1,
                7 => f.rows[0].acknowledgement = NormalAcknowledgement::CallerCheckpoint,
                8 => f.meta.sequences.1 -= 1,
                9 => f.meta.totals.1.completed -= 1,
                10 => f.meta.legacy = false,
                11 => f.meta.next += 1,
                _ => f.meta.tid += 1,
            }
            assert!(f.check().is_err(), "mutation{k}");
        }
        let mut f = fixture();
        f.rows.pop();
        assert_eq!(f.check(), Err(Error::Population));
        let mut f = fixture();
        f.rows.push(f.rows[0]);
        assert_eq!(f.check(), Err(Error::Population));
    }
    #[test]
    fn reference_journal_checks_every_word_and_coherent_prefix_corruption() {
        for word in 0..512 {
            let mut f = fixture();
            f.journal[word] ^= 1;
            assert_eq!(f.check(), Err(Error::Journal), "word{word}");
        }
        let mut f = fixture();
        for row in &mut f.rows {
            row.history_prefix = 2;
        }
        for event in 0..48 {
            f.journal[4 + event * 7 + 6] += 1 << 13;
        }
        assert_eq!(f.check(), Err(Error::Record));
    }
    #[test]
    fn reference_report_requires_all_slots_ranks_payloads_and_terminal_identity() {
        for k in 0..12 {
            let mut f = fixture();
            let r = &mut f.reports[0];
            match k {
                0 => r.record.admission.invocation = 1,
                1 => r.record.admission.entry_value ^= 1,
                2 => r.record.terminal = None,
                3 => {
                    r.record.terminal = Some(Terminal::Completed {
                        value: 1,
                        disposition: Disposition::Retained { rank: 0 },
                    })
                }
                4 => {
                    r.record.terminal = Some(Terminal::Completed {
                        value: 0,
                        disposition: Disposition::DroppedAfterBudget,
                    })
                }
                5 => r.payload = None,
                6 => r.payload.as_mut().unwrap().thread = 2,
                7 => r.payload.as_mut().unwrap().start_sequence = 1,
                8 => r.payload.as_mut().unwrap().admission.function = FunctionId(2),
                9 => {
                    r.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                        end: Observation::Value(0),
                        completed_children: 0,
                    }
                }
                10 => {
                    r.record.terminal = Some(Terminal::Completed {
                        value: 0,
                        disposition: Disposition::Retained { rank: 1 },
                    })
                }
                _ => {
                    r.payload.as_mut().unwrap().outcome = PayloadOutcome::Completed {
                        end: Observation::Value(f.rows[0].raw.end.ticks),
                        completed_children: 1,
                    }
                }
            }
            assert_eq!(f.check(), Err(Error::Report), "mutation{k}");
        }
        let mut f = fixture();
        f.reports.pop();
        assert_eq!(f.check(), Err(Error::Population));
        let mut f = fixture();
        f.reports.push(f.reports[0]);
        assert_eq!(f.check(), Err(Error::Population));
        let mut f = fixture();
        f.reports.swap(0, 1);
        assert_eq!(f.check(), Err(Error::Report));
    }
    #[test]
    fn reference_history_requires_exact_publish_remove_and_no_failed_owner() {
        for k in 0..7 {
            let mut f = fixture();
            let g = f.history.actions[0].generation;
            match k {
                0 => f.history.status = ControllerStatus::TerminalFailure,
                1 => f.history.current = Some(g),
                2 => f.history.enabled[0] = false,
                3 => f.history.retained_failed_generation = Some(g),
                4 => f.history.actions[0].current = None,
                5 => f.history.actions[1].function = Some(FunctionId(1)),
                _ => f.history.actions.swap(0, 1),
            }
            assert_eq!(f.check(), Err(Error::History), "mutation{k}");
        }
        let mut f = fixture();
        f.history.actions.pop();
        assert_eq!(f.check(), Err(Error::History));
    }
    #[test]
    fn reference_gap_arithmetic_retains_zero_and_refuses_aux_order_or_overflow() {
        let f = fixture();
        let mut row = f.rows[0];
        let mut r = f.installed[0].reference.enclosure;
        for tick in [0, u64::MAX] {
            r.start.ticks = tick;
            r.end.ticks = tick;
            row.raw.start.ticks = tick;
            row.raw.end.ticks = tick;
            assert_eq!(gaps(r, &row), Ok(Gaps::default()));
        }
        for k in 0..6 {
            r = f.installed[0].reference.enclosure;
            row = f.rows[0];
            match k {
                0 => row.raw.start.aux += 1,
                1 => row.raw.end.aux += 1,
                2 => r.end.aux += 1,
                3 => row.raw.start.ticks = r.start.ticks - 1,
                4 => row.raw.end.ticks = row.raw.start.ticks - 1,
                _ => row.raw.end.ticks = r.end.ticks + 1,
            }
            assert_eq!(gaps(r, &row), Err(Error::Clock));
        }
        let mut f = fixture();
        f.installed[0].reference.observed_pre_call_rsp = u64::MAX - 15;
        assert_eq!(f.check(), Err(Error::Stack));
    }
}
