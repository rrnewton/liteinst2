//! Serial wrapper around the unchanged exact-work join, not a timing model.
use super::super::{join as work, truth};
use rapid_profiler::frontend::Report;
use rapid_profiler::frontend_native::{
    CallResult, OriginalCallResult, PairTotals, RawInterval, ReferenceInterval, ReferenceLeg,
    ReferenceTimestamp,
};
use rapid_profiler::generation::{FunctionId, GenerationId};

pub(super) const CALLS: usize = work::CALLS;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Config,
    Identity,
    Label,
    Sequence,
    Stack,
    Clock,
    Value,
    Incomplete,
    Poisoned,
    Extra,
    Work(work::JoinError),
}

/// Pre-call descriptor/actual-thread identity, never learned from an observed row.
#[derive(Clone, Copy)]
pub(super) struct Expected {
    pub gate: u64,
    pub pid: u64,
    pub tid: u64,
    pub target: u64,
    pub continuation: u64,
    pub return_pc: u64,
}

/// Copy of a real opaque SDK result. No inverse conversion or invocation token.
/// Internal fields permit targeted metadata mutations in this module's tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Enclosure {
    pub leg: ReferenceLeg,
    pub external_id: u64,
    pub gate: u64,
    pub sequence: u64,
    pub pid: u64,
    pub tid: u64,
    pub target: u64,
    pub continuation: u64,
    pub pre_call_rsp: u64,
    pub resumed_rsp: u64,
    pub start: ReferenceTimestamp,
    pub end: ReferenceTimestamp,
}
impl From<ReferenceInterval> for Enclosure {
    fn from(r: ReferenceInterval) -> Self {
        Self {
            leg: r.leg(),
            external_id: r.external_id(),
            gate: r.gate_identity(),
            sequence: r.gate_sequence(),
            pid: r.pid(),
            tid: r.tid(),
            target: r.target(),
            continuation: r.continuation(),
            pre_call_rsp: r.pre_call_rsp(),
            resumed_rsp: r.resumed_rsp(),
            start: r.start(),
            end: r.end(),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Gaps {
    pub enclosure: u64,
    pub raw: u64,
    pub entry: u64,
    pub exit: u64,
}
fn gaps(reference: Enclosure, row: RawInterval) -> Result<Gaps, Error> {
    if [
        reference.start.aux,
        reference.end.aux,
        row.start.aux,
        row.end.aux,
    ]
    .iter()
    .any(|&a| a != reference.start.aux)
    {
        return Err(Error::Clock);
    }
    let enclosure = reference
        .end
        .ticks
        .checked_sub(reference.start.ticks)
        .ok_or(Error::Clock)?;
    let entry = row
        .start
        .ticks
        .checked_sub(reference.start.ticks)
        .ok_or(Error::Clock)?;
    let raw = row
        .end
        .ticks
        .checked_sub(row.start.ticks)
        .ok_or(Error::Clock)?;
    let exit = reference
        .end
        .ticks
        .checked_sub(row.end.ticks)
        .ok_or(Error::Clock)?;
    if entry.checked_add(raw).and_then(|v| v.checked_add(exit)) != Some(enclosure) {
        return Err(Error::Clock);
    }
    Ok(Gaps {
        enclosure,
        raw,
        entry,
        exit,
    })
}
fn stack(reference: Enclosure, pre: u64, resumed: u64) -> Result<(), Error> {
    if pre < 8
        || pre % 16 != 0
        || pre != resumed
        || (reference.pre_call_rsp, reference.resumed_rsp) != (pre, resumed)
    {
        return Err(Error::Stack);
    }
    Ok(())
}
struct Plan {
    expected: Expected,
    labels: [work::Label; CALLS],
    values: [u64; CALLS],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Original {
    pub label: work::Label,
    pub call: OriginalCallResult,
    pub reference: Enclosure,
    pub work: work::Work,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InstalledReference {
    pub reference: Enclosure,
    pub gaps: Gaps,
}
struct State {
    plan: Plan,
    originals: [Option<Original>; CALLS],
    installed: [Option<InstalledReference>; CALLS],
    originals_next: usize,
    next: usize,
    last_sequence: Option<u64>,
    last_end: Option<u64>,
    aux: Option<u32>,
    poisoned: bool,
}
impl State {
    fn check(&self, r: Enclosure, label: work::Label, leg: ReferenceLeg) -> Result<(), Error> {
        let e = self.plan.expected;
        if (r.gate, r.pid, r.tid, r.target, r.continuation)
            != (e.gate, e.pid, e.tid, e.target, e.continuation)
            || r.leg != leg
        {
            return Err(Error::Identity);
        }
        if r.external_id != label.external_id {
            return Err(Error::Label);
        }
        // The first actual original result establishes the gate baseline. Earlier
        // calibration/Legacy calls are allowed; a raw ordinal never supplies it.
        if r.sequence == 0
            || self
                .last_sequence
                .is_some_and(|s| s.checked_add(1) != Some(r.sequence))
        {
            return Err(Error::Sequence);
        }
        if r.end.ticks < r.start.ticks
            || r.start.aux != r.end.aux
            || self.aux.is_some_and(|a| a != r.start.aux)
            || self.last_end.is_some_and(|end| r.start.ticks < end)
        {
            return Err(Error::Clock);
        }
        Ok(())
    }
    fn advance(&mut self, r: Enclosure) {
        self.last_sequence = Some(r.sequence);
        self.last_end = Some(r.end.ticks);
        self.aux = Some(r.start.aux);
        self.poisoned = false;
    }
}

pub(super) struct Originals {
    state: State,
}
impl Originals {
    pub fn new(expected: Expected, ids: [u64; CALLS], values: [u64; CALLS]) -> Result<Self, Error> {
        if expected.gate == 0
            || expected.pid == 0
            || expected.tid == 0
            || expected.target == 0
            || expected.continuation == 0
            || expected.return_pc <= expected.target
        {
            return Err(Error::Config);
        }
        for i in 0..CALLS {
            if ids[..i].contains(&ids[i]) {
                return Err(Error::Config);
            }
        }
        let lengths = work::Schedule::Alternating.lengths();
        Ok(Self {
            state: State {
                plan: Plan {
                    expected,
                    labels: std::array::from_fn(|i| work::Label {
                        external_id: ids[i],
                        length: lengths[i],
                    }),
                    values,
                },
                originals: [None; CALLS],
                installed: [None; CALLS],
                originals_next: 0,
                next: 0,
                last_sequence: None,
                last_end: None,
                aux: None,
                poisoned: false,
            },
        })
    }
    pub fn labels(&self) -> [work::Label; CALLS] {
        self.state.plan.labels
    }
    pub fn record(
        &mut self,
        label: work::Label,
        call: OriginalCallResult,
        r: Enclosure,
    ) -> Result<(), Error> {
        let s = &mut self.state;
        if s.poisoned {
            return Err(Error::Poisoned);
        }
        s.poisoned = true;
        let i = s.originals_next;
        if i == CALLS {
            return Err(Error::Extra);
        }
        if s.plan.labels[i] != label {
            return Err(Error::Label);
        }
        s.check(r, label, ReferenceLeg::Original)?;
        stack(r, call.pre_call_rsp, call.resumed_rsp)?;
        if call.value != s.plan.values[i] {
            return Err(Error::Value);
        }
        let (instructions, branches, taken, reads) =
            truth::counts(label.length).map_err(|_| Error::Config)?;
        let work = work::Work {
            instructions: instructions as u64,
            branches: branches as u64,
            taken_branches: taken as u64,
            input_byte_reads: (reads - 1) as u64,
            return_read_bytes: 8,
        };
        s.originals[i] = Some(Original {
            label,
            call,
            reference: r,
            work,
        });
        s.originals_next += 1;
        s.advance(r);
        Ok(())
    }
    pub fn installed(
        self,
        generation: GenerationId,
        function: FunctionId,
        thread: u64,
    ) -> Result<Installed, Error> {
        let s = self.state;
        if s.poisoned {
            return Err(Error::Poisoned);
        }
        if s.originals_next != CALLS || s.originals.iter().any(Option::is_none) {
            return Err(Error::Incomplete);
        }
        let exact = work::Trial::new(work::TrialConfig {
            schedule: work::Schedule::Alternating,
            retained: CALLS,
            external_ids: s.plan.labels.map(|l| l.external_id),
            expected_values: s.plan.values,
            generation,
            function,
            thread,
            entry_pc: s.plan.expected.target,
            return_pc: s.plan.expected.return_pc,
        })
        .map_err(Error::Work)?;
        Ok(Installed { exact, state: s })
    }
}

pub(super) struct Installed {
    exact: work::Trial,
    state: State,
}
#[must_use]
pub(super) struct Pending<'a> {
    exact: work::Pending<'a>,
    state: &'a mut State,
    label: work::Label,
}
impl Installed {
    pub fn labels(&self) -> [work::Label; CALLS] {
        self.exact.labels()
    }
    pub fn begin(
        &mut self,
        label: work::Label,
        before: &[RawInterval],
    ) -> Result<Pending<'_>, Error> {
        if self.state.poisoned {
            return Err(Error::Poisoned);
        }
        self.state.poisoned = true;
        if self.state.next == CALLS {
            return Err(Error::Extra);
        }
        let exact = self.exact.begin(label, before).map_err(Error::Work)?;
        Ok(Pending {
            exact,
            state: &mut self.state,
            label,
        })
    }
    pub fn validate(
        &self,
        rows: &[RawInterval],
        totals: PairTotals,
        report: &Report,
    ) -> Result<work::Summary, Error> {
        self.complete()?;
        self.exact
            .validate(rows, totals, report)
            .map_err(Error::Work)
    }
    fn complete(&self) -> Result<(), Error> {
        if self.state.poisoned {
            return Err(Error::Poisoned);
        }
        if self.state.next != CALLS || self.state.installed.iter().any(Option::is_none) {
            return Err(Error::Incomplete);
        }
        Ok(())
    }
    pub fn originals(&self) -> impl Iterator<Item = &Original> {
        self.state.originals.iter().flatten()
    }
    pub fn joined(&self) -> impl Iterator<Item = (&work::JoinedCall, &InstalledReference)> {
        self.exact
            .joined()
            .zip(self.state.installed.iter().flatten())
    }
}
impl Pending<'_> {
    pub fn finish(
        self,
        after: &[RawInterval],
        call: CallResult,
        r: Enclosure,
    ) -> Result<(), Error> {
        let s = self.state;
        s.check(r, self.label, ReferenceLeg::Installed)?;
        stack(r, call.pre_call_rsp, call.resumed_rsp)?;
        let row = after
            .get(s.next)
            .copied()
            .ok_or(Error::Work(work::JoinError::RowCount))?;
        let gaps = gaps(r, row)?;
        // Full old prefix/length/ordinal/owner/value/RSP/clock validation remains
        // one real invocation per old non-Clone Pending, with no bypass on error.
        self.exact.finish(after, call).map_err(Error::Work)?;
        s.installed[s.next] = Some(InstalledReference { reference: r, gaps });
        s.next += 1;
        s.advance(r);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
