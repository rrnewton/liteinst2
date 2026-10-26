//! Retired mm evidence remains visible without becoming native authority.
use super::*;
use crate::gate::OraclePhaseMetrics;

impl ExecState {
    pub(super) fn add_retired_metrics(
        &self,
        census: &ResumeCensus,
        metrics: &mut DynamicAdmissionMetrics,
    ) -> Result<(), GateError> {
        let Some(retired) = &self.retired else {
            return Ok(());
        };
        retired.domain.audit_history()?;
        let binding = retired.census.binding();
        let attempt = self
            .attempt
            .as_ref()
            .ok_or_else(|| refused("retired exec attempt is absent"))?;
        let layout = attempt
            .layout
            .as_ref()
            .ok_or_else(|| refused("retired exec bootstrap layout is absent"))?;
        let transition = attempt
            .transition
            .as_ref()
            .ok_or_else(|| refused("retired exec transition is absent"))?;
        if binding.space != retired.island.address_space
            || binding.generation != retired.island.generation
            || binding.generation != retired.domain.generation
            || retired.origins.len() != 1
            || !retired
                .census
                .rows()
                .all(|row| row.initial.task.address_space == binding.space)
            || retired
                .origins
                .values()
                .any(|origin| !retired.census.rows().any(|row| row.id == *origin))
            || transition.previous().address_space != binding.space
            || transition.current() != layout.stop.identity
            || layout.original_executables.is_empty()
            || layout.original_executables.iter().any(|original| {
                !layout.mappings.iter().any(|map| {
                    map.start == original.start
                        && map.end == original.end
                        && map.file_offset == original.file_offset
                        && map.pathname == original.pathname
                        && map.permissions.as_bytes().get(2) == Some(&b'-')
                })
            })
        {
            return Err(refused(
                "exec retired mm identity or retained origin differs",
            ));
        }
        let (charged, used) = retired.census.accounting_at_retirement();
        for (old, live) in [(charged, census.charged()), (used, census.used())] {
            if old.epochs > live.epochs
                || old.source_fact_bytes > live.source_fact_bytes
                || old.reports > live.reports
                || old.origins > live.origins
                || old.witnesses > live.witnesses
                || old.plan_history > live.plan_history
            {
                return Err(refused(
                    "exec lifetime account moved backwards after retirement",
                ));
            }
        }
        metrics.retained_origins =
            budget::add(metrics.retained_origins, retired.census.rows().count())?;
        metrics.continuation_history_records = budget::add(
            metrics.continuation_history_records,
            retired.census.history().len(),
        )?;
        metrics.retained_call_obligations = budget::add(
            metrics.retained_call_obligations,
            retired.domain.returns.obligations().count(),
        )?;
        metrics.oldest_call_generation = metrics
            .oldest_call_generation
            .into_iter()
            .chain(
                retired
                    .domain
                    .returns
                    .obligations()
                    .map(|call| call.source_generation.0),
            )
            .min();
        for state in [
            &retired.bootstrap.exec_event,
            &retired.bootstrap.exec_exit,
            &retired.bootstrap.entry_trap,
            &retired.bootstrap.restored_entry,
        ] {
            metrics.bootstrap_xstate_bytes =
                budget::add(metrics.bootstrap_xstate_bytes, state.xstate.len())?;
        }
        let old = retired.domain.oracle.metrics();
        add_phase(&mut metrics.oracle.preparation, &old.preparation);
        add_phase(&mut metrics.oracle.demand, &old.demand);
        Ok(())
    }
}

// Match the existing oracle metric's saturation semantics. Overflow remains
// visibly marked; it never becomes a smaller apparently exact measurement.
fn add_phase(live: &mut OraclePhaseMetrics, old: &OraclePhaseMetrics) {
    live.saturated |= old.saturated;
    for (counter, increment) in [
        (&mut live.inspections, old.inspections),
        (&mut live.hits, old.hits),
        (&mut live.runtime_scans, old.runtime_scans),
        (&mut live.no_entry, old.no_entry),
        (&mut live.stale, old.stale),
        (&mut live.corrupt, old.corrupt),
        (&mut live.refused, old.refused),
        (&mut live.decoded_starts, old.decoded_starts),
    ] {
        let sum = counter.checked_add(increment);
        live.saturated |= sum.is_none();
        *counter = sum.unwrap_or(u64::MAX);
    }
    for (counter, increment) in [
        (&mut live.lookup_elapsed, old.lookup_elapsed),
        (&mut live.fresh_scan_elapsed, old.fresh_scan_elapsed),
        (&mut live.store_elapsed, old.store_elapsed),
    ] {
        let sum = counter.checked_add(increment);
        live.saturated |= sum.is_none();
        *counter = sum.unwrap_or(Duration::MAX);
    }
}
