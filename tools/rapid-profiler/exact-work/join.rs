//! Fixed serial experiment bookkeeping, not a clock or instrumentation API.
//! Work counts assume the separately authenticated exact assembly fixture.

use rapid_profiler::frontend::{Observation, PayloadOutcome, RecordObservation, Report};
use rapid_profiler::frontend_native::{CallResult, PairTotals, RawInterval, RawIntervalOwner};
use rapid_profiler::generation::{Disposition, FunctionId, GenerationId, Terminal};

pub const CALLS: usize = 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Schedule {
    AllShort,
    AllLong,
    Alternating,
    TenShortThenLong,
}
impl Schedule {
    pub fn lengths(self) -> [usize; CALLS] {
        std::array::from_fn(|i| match self {
            Self::AllShort => 1,
            Self::AllLong => 64,
            Self::Alternating => {
                if i % 2 == 0 {
                    1
                } else {
                    64
                }
            }
            Self::TenShortThenLong => {
                if i < 10 {
                    1
                } else {
                    64
                }
            }
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Label {
    pub external_id: u64,
    pub length: usize,
}

/// Fixed before any invocation. Values come from the independent scalar model;
/// PCs come from the exact fixture certificate, never from an observed row.
/// Each trial needs a fresh attachment/thread sequence and one armed epoch.
pub struct TrialConfig {
    pub schedule: Schedule,
    pub retained: usize,
    pub external_ids: [u64; CALLS],
    pub expected_values: [u64; CALLS],
    pub generation: GenerationId,
    pub function: FunctionId,
    pub thread: u64,
    pub entry_pc: u64,
    pub return_pc: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Work {
    pub instructions: u64,
    pub branches: u64,
    pub taken_branches: u64,
    pub input_byte_reads: u64,
    pub return_read_bytes: u64,
}
impl Work {
    fn for_length(n: usize) -> Self {
        let n = n as u64;
        Self {
            instructions: 6 * n + 5,
            branches: n,
            taken_branches: n - 1,
            input_byte_reads: n,
            return_read_bytes: 8,
        }
    }
    fn add(&mut self, rhs: Self) {
        self.instructions += rhs.instructions;
        self.branches += rhs.branches;
        self.taken_branches += rhs.taken_branches;
        self.input_byte_reads += rhs.input_byte_reads;
        self.return_read_bytes += rhs.return_read_bytes;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JoinedCall {
    pub label: Label,
    pub raw: RawInterval,
    pub call: CallResult,
    pub work: Work,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Summary {
    pub population: Work,
    pub retained: Work,
    pub population_calls: usize,
    pub retained_calls: usize,
    /// Exact retained-minus-population mean original-instruction count.
    /// These are work units, not ticks, PMU counts, or elapsed time.
    pub selection_error_numerator: i64,
    pub selection_error_denominator: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JoinError {
    Config,
    DuplicateId,
    Poisoned,
    ExtraCall,
    Label,
    RowCount,
    PriorRow,
    Ordinal,
    Boundary,
    Owner,
    Value,
    Stack,
    Clock,
    Incomplete,
    Totals,
    ReportGeneration,
    RecordCount,
    Admission,
    Terminal,
    Payload,
}

pub struct Trial {
    config: TrialConfig,
    labels: [Label; CALLS],
    calls: [Option<JoinedCall>; CALLS],
    next: usize,
    poisoned: bool,
}

/// Non-Clone serial join token. Dropping it or returning any error leaves the
/// trial poisoned. The caller must place exactly one synchronous invocation
/// between begin and finish; no row itself carries an external ID.
#[must_use]
pub struct Pending<'a> {
    trial: &'a mut Trial,
}

impl Trial {
    pub fn new(config: TrialConfig) -> Result<Self, JoinError> {
        if !matches!(config.retained, 1 | 10 | 24)
            || config.thread == 0
            || config.entry_pc == 0
            || config.return_pc <= config.entry_pc
        {
            return Err(JoinError::Config);
        }
        for i in 0..CALLS {
            if config.external_ids[..i].contains(&config.external_ids[i]) {
                return Err(JoinError::DuplicateId);
            }
        }
        let lengths = config.schedule.lengths();
        let labels = std::array::from_fn(|i| Label {
            external_id: config.external_ids[i],
            length: lengths[i],
        });
        Ok(Self {
            config,
            labels,
            calls: [None; CALLS],
            next: 0,
            poisoned: false,
        })
    }
    pub fn labels(&self) -> [Label; CALLS] {
        self.labels
    }
    pub fn joined(&self) -> impl Iterator<Item = &JoinedCall> {
        self.calls.iter().flatten()
    }

    fn prefix(&self, rows: &[RawInterval], count: usize) -> Result<(), JoinError> {
        if rows.len() != count {
            return Err(JoinError::RowCount);
        }
        for (i, row) in rows.iter().take(self.next).enumerate() {
            if self.calls[i].as_ref().map(|c| c.raw) != Some(*row) {
                return Err(JoinError::PriorRow);
            }
        }
        Ok(())
    }

    pub fn begin(
        &mut self,
        label: Label,
        before: &[RawInterval],
    ) -> Result<Pending<'_>, JoinError> {
        if self.poisoned {
            return Err(JoinError::Poisoned);
        }
        self.poisoned = true;
        if self.next == CALLS {
            return Err(JoinError::ExtraCall);
        }
        if label != self.labels[self.next] {
            return Err(JoinError::Label);
        }
        self.prefix(before, self.next)?;
        Ok(Pending { trial: self })
    }

    pub fn validate(
        &self,
        rows: &[RawInterval],
        totals: PairTotals,
        report: &Report,
    ) -> Result<Summary, JoinError> {
        let records: Vec<_> = report.records().take(CALLS + 1).collect();
        self.validate_records(rows, totals, report.generation(), &records)
    }

    fn validate_records(
        &self,
        rows: &[RawInterval],
        totals: PairTotals,
        generation: GenerationId,
        records: &[RecordObservation],
    ) -> Result<Summary, JoinError> {
        if self.poisoned {
            return Err(JoinError::Poisoned);
        }
        if self.next != CALLS {
            return Err(JoinError::Incomplete);
        }
        self.prefix(rows, CALLS)?;
        let k = self.config.retained;
        if totals
            != (PairTotals {
                entries: 24,
                returns: 24,
                completed: k as u64,
                unsampled: (CALLS - k) as u64,
            })
        {
            return Err(JoinError::Totals);
        }
        if generation != self.config.generation {
            return Err(JoinError::ReportGeneration);
        }
        if records.len() != k {
            return Err(JoinError::RecordCount);
        }
        for (rank, (record, row)) in records.iter().zip(rows).enumerate() {
            let admission = record.record.admission;
            if admission.generation != generation
                || admission.function != self.config.function
                || admission.invocation != rank
                || admission.entry_value != row.start.ticks
            {
                return Err(JoinError::Admission);
            }
            if record.record.terminal
                != Some(Terminal::Completed {
                    value: rank as u64,
                    disposition: Disposition::Retained { rank },
                })
            {
                return Err(JoinError::Terminal);
            }
            let payload = record.payload.ok_or(JoinError::Payload)?;
            if payload.admission != admission
                || payload.thread != self.config.thread
                || payload.start_sequence != rank as u64
                || payload.outcome
                    != (PayloadOutcome::Completed {
                        end: Observation::Value(row.end.ticks),
                        completed_children: 0,
                    })
            {
                return Err(JoinError::Payload);
            }
        }
        let (mut population, mut retained) = (Work::default(), Work::default());
        for (i, call) in self.joined().enumerate() {
            population.add(call.work);
            if i < k {
                retained.add(call.work);
            }
        }
        Ok(Summary {
            population,
            retained,
            population_calls: CALLS,
            retained_calls: k,
            selection_error_numerator: (retained.instructions * CALLS as u64) as i64
                - (population.instructions * k as u64) as i64,
            selection_error_denominator: (k * CALLS) as u64,
        })
    }
}

impl Pending<'_> {
    pub fn finish(self, after: &[RawInterval], call: CallResult) -> Result<(), JoinError> {
        let trial = self.trial;
        let i = trial.next;
        trial.prefix(after, i + 1)?;
        let row = after[i];
        if row.ordinal != i as u64 + 1 {
            return Err(JoinError::Ordinal);
        }
        if row.entry_pc != trial.config.entry_pc
            || row.return_pc != trial.config.return_pc
            || call.return_pc != trial.config.return_pc
        {
            return Err(JoinError::Boundary);
        }
        let generation = trial.config.generation.get();
        let owner = if i < trial.config.retained {
            RawIntervalOwner::Sampled {
                generation,
                invocation: i,
            }
        } else {
            RawIntervalOwner::FunctionClosed { generation }
        };
        if row.owner != owner {
            return Err(JoinError::Owner);
        }
        if call.value != trial.config.expected_values[i] {
            return Err(JoinError::Value);
        }
        if call.pre_call_rsp != call.resumed_rsp
            || call.entry_rsp.checked_add(8) != Some(call.pre_call_rsp)
        {
            return Err(JoinError::Stack);
        }
        if row.elapsed_ticks().is_none() {
            return Err(JoinError::Clock);
        }
        trial.calls[i] = Some(JoinedCall {
            label: trial.labels[i],
            raw: row,
            call,
            work: Work::for_length(trial.labels[i].length),
        });
        trial.next += 1;
        trial.poisoned = false;
        Ok(())
    }
}

#[cfg(test)]
#[path = "join/tests.rs"]
mod tests;
