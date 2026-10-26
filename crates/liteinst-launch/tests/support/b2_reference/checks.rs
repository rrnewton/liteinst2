//! Private shared provider and exact comparator checks. No production backend.
use super::*;

#[derive(Clone)]
pub(super) struct Replay {
    rows: Vec<Row>,
    pub(super) calls: usize,
}
impl Replay {
    pub(super) fn new(rows: &[Row]) -> Self {
        Self {
            rows: rows.to_vec(),
            calls: 0,
        }
    }
}
impl InstructionProvider for Replay {
    fn decide(&mut self, input: &SelectedInput) -> Result<ProviderDecision, SemanticsError> {
        let row = self
            .rows
            .get(self.calls)
            .ok_or(SemanticsError::ScriptMismatch)?;
        if input.registers() != &row.before.registers
            || input.instruction().logical_pc() != row.before.registers.rip
            || input.instruction().bytes() != row.bytes
            || input.instruction().operation().class() != row.selected.class()
        {
            return Err(SemanticsError::ScriptMismatch);
        }
        self.calls += 1;
        Ok(ProviderDecision::Complete(row.reply.result()))
    }
}
pub(super) fn check_completion(actual: &SelectedCompletion, row: &Row) {
    assert_eq!(actual.execution, SelectedExecution::Scripted);
    assert_eq!(actual.input.registers(), &row.before.registers);
    assert_eq!(
        actual.input.instruction().logical_pc(),
        row.before.registers.rip
    );
    assert_eq!(actual.input.instruction().bytes(), row.bytes);
    assert_eq!(
        actual.input.instruction().operation().class(),
        row.selected.class()
    );
    assert_eq!(actual.before_xstate, row.before.xstate);
    assert_eq!(actual.after, row.after.registers);
    assert_eq!(actual.xstate, row.after.xstate);
}
pub(super) fn check_metrics(metrics: &SelectedMetrics, rows: &[Row]) {
    let mut counts = BTreeMap::new();
    for row in rows {
        *counts.entry(row.selected.class()).or_insert(0) += 1;
    }
    assert_eq!(metrics.callbacks, counts);
    assert_eq!(metrics.scripted_completions, rows.len());
    assert_eq!(metrics.native_completions, 0);
    assert_eq!(metrics.provider_faults, 0);
    assert_eq!(metrics.native_signals, 0);
    assert_eq!(metrics.refusals, 0);
}
pub(super) fn rethrow<T>(result: std::thread::Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
