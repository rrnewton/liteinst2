use super::super::super::RawInterval;
use super::*;
use std::ops::Range;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    pid: u32,
    tid: u64,
    registration: u64,
    install: u64,
    function: FunctionId,
    base: u64,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Cursor {
    pub(super) number: u64,
    pub(super) totals: OptionalTotals,
    identity: Option<Identity>,
    after: Option<Duration>,
}
// This projection is built only from a sealed OptionalIntervalBatch in production.
// The frontend owns full event encoding validation; this function joins every
// actual physical return to the sparse observed rows and full transferred page.
struct View<'a> {
    identity: Identity,
    number: u64,
    before: OptionalTotals,
    after: OptionalTotals,
    completed: (u64, u64),
    gate: u64,
    next: u64,
    physical: Range<u64>,
    raw: Range<u64>,
    events: Range<u64>,
    rows: &'a [RawInterval],
    joins: &'a [u64],
    journal: &'a [u64],
    prefixes: [Option<u64>; ROWS * 2],
    calls: &'a [Option<OptionalCompletedCall>; ROWS],
}
impl Cursor {
    pub(super) fn accept(
        &mut self,
        packet: &OptionalCompletedBatch,
        stream: &HistoryStream,
    ) -> Result<(), Error> {
        let b = &packet.native;
        if b.history_stream() != Some(stream) {
            return Err(Error::Owner);
        }
        let (before, after) = b.totals();
        let v = View {
            identity: Identity {
                pid: b.pid(),
                tid: b.tid(),
                registration: b.registration(),
                install: b.install(),
                function: b.function(),
                base: b.gate_base(),
            },
            number: b.number(),
            before,
            after,
            completed: b.completed_sequences(),
            gate: b.gate_sequence(),
            next: b.next_ordinal(),
            physical: b.physical_range(),
            raw: b.raw_range(),
            events: b.event_range(),
            rows: b.rows(),
            joins: b.observed_gate_sequences(),
            journal: b.journal(),
            prefixes: std::array::from_fn(|i| b.history_prefix(i)),
            calls: &packet.calls,
        };
        *self = accept(*self, &v)?;
        Ok(())
    }
}
fn accept(old: Cursor, v: &View<'_>) -> Result<Cursor, Error> {
    let count = v
        .after
        .physical
        .checked_sub(v.before.physical)
        .ok_or(Error::Sequence)?;
    if !(1..=ROWS as u64).contains(&count) {
        return Err(Error::Sequence);
    }
    let count = count as usize;
    let slow = v
        .after
        .observed
        .returns
        .checked_sub(v.before.observed.returns)
        .ok_or(Error::Sequence)?;
    let fast = v
        .after
        .bypassed
        .checked_sub(v.before.bypassed)
        .ok_or(Error::Sequence)?;
    let sampled = v
        .after
        .observed
        .completed
        .checked_sub(v.before.observed.completed)
        .ok_or(Error::Sequence)?;
    let unsampled = v
        .after
        .observed
        .unsampled
        .checked_sub(v.before.observed.unsampled)
        .ok_or(Error::Sequence)?;
    if v.before != old.totals
        || old.number.checked_add(1) != Some(v.number)
        || !balanced_optional(v.before)
        || !balanced_optional(v.after)
        || old.identity.is_some_and(|id| id != v.identity)
        || v.identity.pid == 0
        || v.identity.tid == 0
        || v.identity.registration == 0
        || slow.checked_add(fast) != Some(count as u64)
        || sampled.checked_add(unsampled) != Some(slow)
        || slow != v.rows.len() as u64
        || v.rows.len() != v.joins.len()
        || v.rows.len() > count
        || v.physical != (v.before.physical..v.after.physical)
        || v.raw != (v.before.observed.returns..v.after.observed.returns)
        || v.before.observed.returns.checked_mul(2) != Some(v.events.start)
        || v.after.observed.returns.checked_mul(2) != Some(v.events.end)
        || v.completed != (v.before.observed.completed, v.after.observed.completed)
        || v.after.observed.entries.checked_add(1) != Some(v.next)
        || v.identity.base.checked_add(v.after.physical) != Some(v.gate)
        || v.calls[count..].iter().any(Option::is_some)
        || v.journal.len() != 512
    {
        return Err(Error::Sequence);
    }
    if v.journal[..4] != [slow * 2, 0, v.identity.tid, 0]
        || v.journal[4 + v.rows.len() * 14..].iter().any(|&x| x != 0)
        || v.prefixes[v.rows.len() * 2..].iter().any(Option::is_some)
    {
        return Err(Error::Sequence);
    }
    let mut row = 0;
    let mut fast_seen = 0;
    let mut sampled_seen = 0;
    let mut after = old.after;
    for i in 0..count {
        let c = v.calls[i].ok_or(Error::Sequence)?;
        let r = c.result;
        let physical = v
            .before
            .physical
            .checked_add(i as u64)
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Sequence)?;
        if r.physical != physical
            || v.identity.base.checked_add(physical) != Some(r.gate_sequence)
            || c.before > c.after
            || after.is_some_and(|t| t > c.before)
            || r.pre_call_rsp != r.resumed_rsp
            || r.entry_rsp.checked_add(8) != Some(r.pre_call_rsp)
        {
            return Err(Error::Sequence);
        }
        match r.path {
            OptionalPath::FastBypass => fast_seen += 1,
            OptionalPath::Slow { ordinal } => {
                let raw = v.rows.get(row).ok_or(Error::Sequence)?;
                let event = 4 + row * 14;
                if v.before
                    .observed
                    .returns
                    .checked_add(row as u64)
                    .and_then(|n| n.checked_add(1))
                    != Some(ordinal)
                    || raw.ordinal != ordinal
                    || raw.return_pc != r.return_pc
                    || v.journal[event + 3] != r.entry_rsp
                    || v.journal[event + 10] != r.entry_rsp
                    || v.joins.get(row) != Some(&r.gate_sequence)
                    || v.prefixes[row * 2].is_none()
                    || v.prefixes[row * 2] != v.prefixes[row * 2 + 1]
                {
                    return Err(Error::Sequence);
                }
                sampled_seen += u64::from(matches!(raw.owner, RawIntervalOwner::Sampled { .. }));
                row += 1;
            }
        }
        after = Some(c.after);
    }
    if row != v.rows.len() || fast_seen != fast || sampled_seen != sampled {
        return Err(Error::Sequence);
    }
    Ok(Cursor {
        number: v.number,
        totals: v.after,
        identity: Some(v.identity),
        after,
    })
}

#[cfg(test)]
mod tests {
    use super::super::super::super::RawTimestamp;
    use super::*;
    fn call(n: u64, path: OptionalPath) -> OptionalCompletedCall {
        OptionalCompletedCall {
            length: 64,
            result: OptionalCallResult {
                physical: n,
                gate_sequence: 96 + n,
                path,
                value: 17,
                pre_call_rsp: 0x8010,
                entry_rsp: 0x8008,
                resumed_rsp: 0x8010,
                return_pc: 0x1020,
            },
            before: Duration::from_nanos(n * 10),
            after: Duration::from_nanos(n * 10 + 1),
        }
    }
    struct Fixture {
        calls: [Option<OptionalCompletedCall>; ROWS],
        rows: Vec<RawInterval>,
        joins: Vec<u64>,
        page: [u64; 512],
    }
    impl Fixture {
        fn mixed() -> Self {
            let rows = vec![RawInterval {
                ordinal: 1,
                entry_pc: 0x1000,
                return_pc: 0x1020,
                owner: RawIntervalOwner::Sampled {
                    generation: 7,
                    invocation: 0,
                },
                start: RawTimestamp { ticks: 10, aux: 1 },
                end: RawTimestamp { ticks: 20, aux: 1 },
            }];
            let mut page = [0; 512];
            page[..4].copy_from_slice(&[2, 0, 2, 0]);
            // The immutable Slow entry/exit events name the actual call stack.
            page[7] = 0x8008;
            page[14] = 0x8008;
            Self {
                calls: [
                    Some(call(1, OptionalPath::FastBypass)),
                    Some(call(2, OptionalPath::Slow { ordinal: 1 })),
                    Some(call(3, OptionalPath::FastBypass)),
                    Some(call(4, OptionalPath::FastBypass)),
                ],
                rows,
                joins: vec![98],
                page,
            }
        }
        fn view(&self) -> View<'_> {
            View {
                identity: Identity {
                    pid: 1,
                    tid: 2,
                    registration: 1,
                    install: 71,
                    function: FunctionId(11),
                    base: 96,
                },
                number: 1,
                before: OptionalTotals::default(),
                after: OptionalTotals {
                    physical: 4,
                    bypassed: 3,
                    observed: PairTotals {
                        entries: 1,
                        returns: 1,
                        completed: 1,
                        unsampled: 0,
                    },
                },
                completed: (0, 1),
                gate: 100,
                next: 2,
                physical: 0..4,
                raw: 0..1,
                events: 0..2,
                rows: &self.rows,
                joins: &self.joins,
                journal: &self.page,
                prefixes: [Some(599), Some(599), None, None, None, None, None, None],
                calls: &self.calls,
            }
        }
    }
    #[test]
    fn mixed_physical_calls_join_sparse_rows_without_counting_fast_as_unsampled() {
        let f = Fixture::mixed();
        let end = accept(Cursor::default(), &f.view()).unwrap();
        assert_eq!(end.totals.physical, 4);
        assert_eq!(end.totals.bypassed, 3);
        assert_eq!(end.totals.observed.unsampled, 0);
        assert_eq!(end.totals.observed.completed, 1);
        assert_eq!(end.identity.unwrap().base, 96);
    }
    #[test]
    fn fast_only_batch_is_not_empty_and_has_no_history_events() {
        let mut f = Fixture::mixed();
        f.calls[1] = Some(call(2, OptionalPath::FastBypass));
        f.rows.clear();
        f.joins.clear();
        f.page.fill(0);
        f.page[2] = 2;
        let mut v = f.view();
        v.after = OptionalTotals {
            physical: 4,
            bypassed: 4,
            observed: PairTotals::default(),
        };
        v.completed = (0, 0);
        v.next = 1;
        v.raw = 0..0;
        v.events = 0..0;
        v.prefixes = [None; 8];
        let end = accept(Cursor::default(), &v).unwrap();
        assert_eq!(end.totals.bypassed, 4);
        assert_eq!(end.totals.observed.entries, 0);
        v.after.physical = 0;
        assert_eq!(accept(Cursor::default(), &v), Err(Error::Sequence));
    }
    #[test]
    fn omitted_duplicate_swapped_or_fabricated_observation_refuses() {
        for mode in 0..6 {
            let mut f = Fixture::mixed();
            match mode {
                0 => f.calls[1] = None,
                1 => f.calls[2] = f.calls[1],
                2 => f.calls.swap(0, 1),
                3 => f.calls[0].as_mut().unwrap().result.path = OptionalPath::Slow { ordinal: 1 },
                4 => f.joins[0] = 97,
                _ => f.calls[1].as_mut().unwrap().result.return_pc += 1,
            }
            assert_eq!(accept(Cursor::default(), &f.view()), Err(Error::Sequence));
        }
    }
    #[test]
    fn shifted_call_rsp_triple_cannot_replace_either_authenticated_event_rsp() {
        let mut f = Fixture::mixed();
        let r = &mut f.calls[1].as_mut().unwrap().result;
        r.pre_call_rsp += 16;
        r.entry_rsp += 16;
        r.resumed_rsp += 16;
        assert_eq!(r.pre_call_rsp, r.resumed_rsp);
        assert_eq!(r.entry_rsp.checked_add(8), Some(r.pre_call_rsp));
        assert_eq!(accept(Cursor::default(), &f.view()), Err(Error::Sequence));
        for event_rsp in [7, 14] {
            let mut f = Fixture::mixed();
            f.page[event_rsp] += 16;
            assert_eq!(accept(Cursor::default(), &f.view()), Err(Error::Sequence));
        }
    }
    #[test]
    fn counters_identity_page_gate_and_prefix_refusals_do_not_commit() {
        let f = Fixture::mixed();
        let old = Cursor::default();
        for mode in 0..8 {
            let mut v = f.view();
            match mode {
                0 => v.number = 2,
                1 => v.after.bypassed = 2,
                2 => v.gate = 99,
                3 => v.prefixes[1] = Some(600),
                4 => v.raw = 1..2,
                5 => v.completed = (0, 0),
                6 => v.next = 3,
                _ => v.identity.registration = 0,
            }
            assert_eq!(accept(old, &v), Err(Error::Sequence));
            assert_eq!(old, Cursor::default());
        }
        let mut f = Fixture::mixed();
        f.page[511] = 1;
        assert_eq!(accept(old, &f.view()), Err(Error::Sequence));
        let old = Cursor {
            identity: Some(Identity {
                base: 0,
                ..f.view().identity
            }),
            ..Cursor::default()
        };
        assert_eq!(accept(old, &Fixture::mixed().view()), Err(Error::Sequence));
    }
}
